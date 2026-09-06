"""Modbus TCP 适配器实现: probe / read / send_raw (T3 + T4)。

失败分类决策 (PLAN.md 四类):
- ConnectionRefusedError            -> connection_refused (connectivity)
- connect 超时                       -> timeout (connectivity)
- 其它 OSError (网络不可达等)        -> 归入 connection_refused: 四分类没有
  "unreachable" 档, 语义上最接近"无法建立 TCP 连接"
- 已连接后收发超时 / 连接被重置      -> connected_but_no_reply (protocol):
  TCP 通了但应用层没回话
- 收到异常响应帧                     -> exception_response (application):
  设备在线且协议栈正常, 是应用层拒绝

probe 刻意不走连接池: 一次性连接、即用即关, 避免故障注入场景污染池状态。
"""

from __future__ import annotations

import asyncio
import itertools
import struct
from typing import Callable
import time

from plctap.models import (
    ByteOrder,
    ProbeResult,
    RawExchange,
    ReadResult,
    Target,
)
from plctap.protocols import base
from plctap.protocols.base import ProtocolAdapter, register_adapter
from plctap.protocols.modbus import codec
from plctap.protocols.modbus import meta as _meta

_transaction_ids = itertools.count(1)


@register_adapter
class ModbusAdapter(ProtocolAdapter):
    name = "modbus"
    meta = _meta.META

    # ------------------------------------------------------------ 收帧

    async def _recv_response(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> bytes:
        """按 MBAP 长度字段收一帧完整响应 (半包/粘包在这里被正确切分)。"""
        head = await base.recv_exact(reader, codec.MBAP_LEN, timeout)
        (_tid, _pid, length) = struct.unpack_from(">HHH", head, 0)
        # 长度字段合理性: PDU 上限 253 (规范 4.1 节), length=unit(1)+PDU。
        # 明显越界说明流已失步或对端在发垃圾, 不给它挂到超时的机会。
        if not 1 <= length <= 254:
            raise ModbusError(f"implausible MBAP length field {length}, aborting read")
        # length = unit(1) + PDU, 其余部分还需 length-1 字节
        rest = await base.recv_exact(reader, length - 1, timeout)
        return head + rest

    # ------------------------------------------ 帧构建/解析钩子 (v0.5: RTU-over-TCP 派生类覆写)

    def _build_read_frame(self, tid: int, unit: int, fc: int, address: int, count: int) -> bytes:
        return codec.build_read_request(tid, unit, fc, address, count)

    def _build_write_single_frame(self, tid: int, unit: int, fc: int, address: int, value: int) -> bytes:
        return codec.build_write_single(tid, unit, fc, address, value)

    def _build_write_multi_frame(self, tid: int, unit: int, address: int, values: list[int]) -> bytes:
        return codec.build_write_multiple(tid, unit, address, values)

    def _parse(self, resp: bytes, request: bytes):
        return codec.parse_response(resp, request=request)

    async def _recv_response_untrusted(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> bytes:
        """send_raw 路径: 响应长度字段不可信时按可用数据收 (codec 去指出问题)。"""
        return await asyncio.wait_for(reader.read(4096), timeout)

    # ------------------------------------------------------------ probe

    async def probe(self, target: Target) -> ProbeResult:
        timeout = self.timeout(None)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout
            )
        except ConnectionRefusedError:
            return ProbeResult(
                reachable=False,
                failure_class="connection_refused",
                layer_hint="connectivity",
            )
        except TimeoutError:
            return ProbeResult(
                reachable=False, failure_class="timeout", layer_hint="connectivity"
            )
        except OSError:
            # 网络不可达 / 路由失败等: 无法细分, 归入无法建立连接
            return ProbeResult(
                reachable=False,
                failure_class="connection_refused",
                layer_hint="connectivity",
            )
        try:
            frame = self._build_read_frame(
                next(_transaction_ids), target.unit, codec.READ_HOLDING_REGISTERS, 0, 1
            )
            writer.write(frame)
            await asyncio.wait_for(writer.drain(), timeout)
            resp = await self._recv_response(reader, timeout)
        except (
            TimeoutError,
            asyncio.IncompleteReadError,
            OSError,
            ConnectionError,
            ModbusError,
        ):
            # TCP 已建立但没拿到可解析的一帧响应: 设备端口通, 应用层没回应
            return ProbeResult(
                reachable=False,
                failure_class="connected_but_no_reply",
                layer_hint="protocol",
            )
        finally:
            writer.close()
        # 带请求上下文解析: tid/unit/fc/byte_count 四重交叉校验,
        # 回显服务器 (把请求原样弹回) 在 byte_count 校验处被识破
        parsed = self._parse(resp, frame)
        if not parsed.valid:
            return ProbeResult(
                reachable=False,
                failure_class="connected_but_no_reply",
                layer_hint="protocol",
            )
        fc_field = next(
            (f for f in parsed.fields if f.name == "function_code"), None
        )
        if fc_field is None:
            return ProbeResult(
                reachable=False,
                failure_class="connected_but_no_reply",
                layer_hint="protocol",
            )
        if isinstance(fc_field.value, int) and fc_field.value & codec.EXCEPTION_FLAG:
            exc = next(
                (f.value for f in parsed.fields if f.name == "exception_code"), None
            )
            # reachable=传输层可达: 设备在线且回了规范异常帧 (P3 语义修正)
            return ProbeResult(
                reachable=True,
                failure_class="exception_response",
                exception_code=exc if isinstance(exc, int) else None,
                layer_hint="application",
            )
        return ProbeResult(reachable=True, layer_hint="application")

    # ------------------------------------------------------------ read

    async def read(
        self,
        target: Target,
        address: int,
        count: int,
        datatype: str | None = None,
        byteorder: ByteOrder = "big",
        timeout_ms: int | None = None,
        function_code: int = codec.READ_HOLDING_REGISTERS,
    ) -> ReadResult:
        """读保持寄存器 (fc03, 默认) 或输入寄存器 (fc04)。

        count = 寄存器个数 (与"读 40001 开始 10 个寄存器"的口语一致);
        interpreted: uint16/int16 每寄存器一个值, float32 两个寄存器合成
        一个值 (不足一对的尾寄存器丢弃, 在 interpreted_note 说明)。

        异常响应在 M1 直接抛 ModbusError 带异常码含义; M2 由 diagnose
        引擎接管错误解释 (HANDOFF 红线: server 不做自然语言叙述)。
        """
        if function_code not in (codec.READ_HOLDING_REGISTERS, codec.READ_INPUT_REGISTERS):
            raise ValueError(f"plc_read supports fc 3/4, got fc{function_code}")
        timeout = self.timeout(timeout_ms)
        tid = next(_transaction_ids)
        request = self._build_read_frame(tid, target.unit, function_code, address, count)
        started = time.perf_counter()
        resp = await self._exchange(target, request, timeout)
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        parsed = self._parse(resp, request)
        fc_field = next(f for f in parsed.fields if f.name == "function_code")
        if isinstance(fc_field.value, int) and fc_field.value & codec.EXCEPTION_FLAG:
            exc = next(
                (f.value for f in parsed.fields if f.name == "exception_code"), 0
            )
            raise ModbusError(
                f"device returned exception {codec.exception_name(int(exc))} (0x{int(exc):02x})"
                f" for fc{function_code} address={address} count={count}"
            )
        if not parsed.valid:
            raise ModbusError(
                "malformed response: " + "; ".join(parsed.errors)
            )
        values_field = next(f for f in parsed.fields if f.name == "register_values")
        raw = list(values_field.value)  # type: ignore[arg-type]
        if len(raw) < count:
            raise ModbusError(
                f"device returned {len(raw)} registers, requested {count}"
            )
        interpreted = codec.interpret_registers(raw, datatype, byteorder)
        return ReadResult(
            target=target,
            address=address,
            request_frame=request.hex(),
            raw_registers=raw,
            interpreted=interpreted,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------ send_raw

    async def send_raw(
        self, target: Target, frame_hex: str, timeout_ms: int | None = None
    ) -> RawExchange:
        """发送任意原始帧并等待一帧响应 (M3, 写闸门后注册为工具)。"""
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        resp = await self._exchange(target, frame, timeout, validate_length=False)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RawExchange(
            target=target,
            sent_frame=frame.hex(),
            received_frame=resp.hex(),
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------ write (M1 P2 修复: 审计真实帧)

    async def write(
        self,
        target: Target,
        address: int,
        values: list[int],
        *,
        on_frame: Callable[[str], None] | None = None,
        point_type: str = "register",
        timeout_ms: int | None = None,
        **kwargs,
    ) -> dict:
        """写寄存器/线圈。

        point_type="register" 默认 fc16 (Write Multiple Registers);
        kwargs._function_code=6 切换 fc06。
        point_type="coil" 使用 fc05 (Write Single Coil)。

        on_frame 在帧构建后、任何网络动作前被调用 —— 审计先于发送,
        即使后续连接失败, 该次写意图与完整帧也已留痕 (D5/红线 2)。
        """
        tid = next(_transaction_ids)
        fc_override = kwargs.pop("_function_code", None)
        if point_type == "coil":
            if len(values) != 1:
                raise ValueError("fc05 writes exactly one coil value")
            request = self._build_write_single_frame(tid, target.unit, codec.WRITE_SINGLE_COIL, address, values[0])
        elif point_type == "register":
            if len(values) == 1 and fc_override == 6:
                # 显式指定 fc06
                request = self._build_write_single_frame(tid, target.unit, codec.WRITE_SINGLE_REGISTER, address, values[0])
            else:
                # 默认 fc16 (Write Multiple Registers) — 兼容绝大多数模拟器
                request = self._build_write_multi_frame(tid, target.unit, address, values)
        else:
            raise ValueError(f"point_type must be 'coil'|'register', got {point_type!r}")
        if on_frame is not None:
            on_frame(request.hex())
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        resp = await self._exchange(target, request, timeout)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        parsed = self._parse(resp, request)
        fc_field = next(f for f in parsed.fields if f.name == "function_code")
        if isinstance(fc_field.value, int) and fc_field.value & codec.EXCEPTION_FLAG:
            exc = next((f.value for f in parsed.fields if f.name == "exception_code"), 0)
            raise ModbusError(
                f"device returned exception {codec.exception_name(int(exc))} (0x{int(exc):02x})"
                f" for address={address} values={values}"
            )
        if not parsed.valid:
            raise ModbusError("malformed write response: " + "; ".join(parsed.errors))
        return {
            "request_frame": request.hex(),
            "response_frame": resp.hex(),
            "elapsed_ms": elapsed_ms,
        }
    # ------------------------------------------------------------ 会话

    async def _exchange(
        self,
        target: Target,
        request: bytes,
        timeout: float,
        *,
        validate_length: bool = True,
    ) -> bytes:
        """一次请求-响应配对: 目标级锁内 取连接 -> 写 -> 读 -> 归还。

        validate_length=False 用于 send_raw (可能收到故障注入的坏长度帧,
        长度字段不可信时按可用数据收, 让上层 codec 去指出问题)。
        """
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            conn = await self.pool.acquire(key, timeout)
            try:
                conn.writer.write(request)
                await asyncio.wait_for(conn.writer.drain(), timeout)
                if validate_length:
                    resp = await self._recv_response(conn.reader, timeout)
                else:
                    resp = await self._recv_response_untrusted(conn.reader, timeout)
            except ModbusError:
                # 长度字段已判定流失步, 连接不可复用
                self.pool.discard(conn)
                raise
            except TimeoutError:
                # 设备没回话: 包装成带上下文的 ModbusError, 便于 Agent 读取
                self.pool.discard(conn)
                raise ModbusError(
                    f"timeout waiting for response from {key.target}"
                ) from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                # 流状态不可信 (可能已失步/被对端关闭): 丢弃连接
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)
                return resp


@register_adapter
class ModbusRtuOverTcpAdapter(ModbusAdapter):
    """Modbus RTU over TCP 适配器 (v0.5): 串口服务器/网关的 RTU 模式。

    线帧 = 从站地址 + PDU + CRC16, 无 MBAP/事务号; PDU 语义与 TCP 完全
    一致 (构建器复用 + rtu_request_from_tcp 转换), 差异只在传输帧壳。
    响应无长度字段, 按 FC 定长切帧 (codec.rtu_response_total_len);
    send_raw 无法预知 FC, 退化为"收到一帧完整 RTU 响应为止"的累积读取。
    """

    name = "modbus_rtu"
    meta = _meta.META_RTU

    def _build_read_frame(self, tid: int, unit: int, fc: int, address: int, count: int) -> bytes:
        return codec.rtu_request_from_tcp(codec.build_read_request(tid, unit, fc, address, count))

    def _build_write_single_frame(self, tid: int, unit: int, fc: int, address: int, value: int) -> bytes:
        return codec.rtu_request_from_tcp(codec.build_write_single(tid, unit, fc, address, value))

    def _build_write_multi_frame(self, tid: int, unit: int, address: int, values: list[int]) -> bytes:
        return codec.rtu_request_from_tcp(codec.build_write_multiple(tid, unit, address, values))

    async def _recv_response(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> bytes:
        """按 FC 定长收一帧 RTU 响应。半包由 recv_exact 逐段补齐。

        读响应 (fc01-04) 的定长依赖第 3 字节 byte_count, 因此先收 2 字节
        判 FC, 读类再补收 1 字节后才问总长。
        """
        head = await base.recv_exact(reader, 2, timeout)
        if head[1] in codec.READ_FCS:
            # 读响应的定长依赖第 3 字节 byte_count
            head += await base.recv_exact(reader, 1, timeout)
        total = codec.rtu_response_total_len(head)
        if total is None:
            # 未知 FC 无法定长: 流可能已失步或对端在发垃圾, 不给它挂到超时的机会
            raise ModbusError(
                f"cannot frame RTU response: unknown function code {head[1]:#04x}"
            )
        rest = await base.recv_exact(reader, total - len(head), timeout)
        return head + rest

    async def _recv_response_untrusted(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> bytes:
        """send_raw 路径: 无法预知 FC, 累积读取直到长度可判定或超时。

        CRC 正确性不在接收层判 —— send_raw 场景要保留完整证据帧交
        parse_frame/validate_frame 分析。
        """
        buf = b""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return buf
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except TimeoutError:
                return buf
            if not chunk:
                return buf
            buf += chunk
            total = codec.rtu_response_total_len(buf)
            if total is not None and len(buf) >= total:
                return buf

    def _parse(self, resp: bytes, request: bytes):
        parsed = codec.parse_rtu(resp, direction="resp")
        # 交叉校验: 从站地址 + 功能码回显 (parse_rtu 无请求上下文, 在此补上,
        # 与 TCP 轨道的 tid/unit/fc 四重校验对齐 —— 网关错路由/串包检测)
        if request:
            if resp and resp[0] != request[0]:
                parsed.errors.append(
                    f"address mismatch: response {resp[0]} != request {request[0]}"
                )
            if len(resp) >= 2 and len(request) >= 2 and resp[1] & 0x7F != request[1] & 0x7F:
                parsed.errors.append(
                    f"function code mismatch: response {resp[1]:#04x} != request {request[1]:#04x}"
                )
            if parsed.errors:
                parsed.valid = False
        return parsed


class ModbusError(RuntimeError):
    """设备返回异常响应或畸形响应时的工具层错误。消息只含事实与异常码
    名称, 叙述性解释由 Agent + Skill 层完成 (D4)。"""

