"""Mitsubishi MELSEC MC 3E 二进制适配器 (M2)。

MC/3E 是无会话协议: 每帧自描述 (副头部+网络/PC 回显), 无握手、无事务号,
直接走通用 locked_exchange。可靠性靠响应与请求的头部回显交叉核对
(codec._cross_check), 这是 3E 场景串包检测的主要手段 —— 也是诊断引擎
的重要素材 (网络号/PC 号配置不符时回显错位)。
"""

from __future__ import annotations

import asyncio
import functools
import struct
import time

from plctap.models import (
    ByteOrder,
    ProbeResult,
    RawExchange,
    ReadResult,
    Target,
)
from plctap.protocols.base import (
    ProtocolAdapter,
    ProtocolError,
    locked_exchange,
    recv_exact,
    register_adapter,
)
from plctap.protocols.melsec import codec
from plctap.protocols.melsec import meta as _meta

FRAME_HEADER_LEN = codec.FRAME_HEADER_LEN


@register_adapter
class MelsecAdapter(ProtocolAdapter):
    name = "melsec"
    meta = _meta.META

    # ------------------------------------------------------------ 收帧

    # 响应副头部 -> 帧格式 (二进制第 2 字节恒 0x00, ASCII 第 2 字节为 '0')
    _RESP_SUBHEADER_TO_FORMAT = {
        b"\xd0\x00": "3e_binary",
        b"\xd4\x00": "4e_binary",
        b"D0": "3e_ascii",
        b"D4": "4e_ascii",
    }

    async def _recv_frame(
        self,
        reader: asyncio.StreamReader,
        timeout: float,
        frame_format: str = "3e_binary",
        _head2: bytes | None = None,
    ) -> bytes:
        """按响应数据长度字段收一帧 (frame_format="auto" 时丢弃判别结果)。"""
        frame, _fmt = await self._recv_frame_auto(reader, timeout, frame_format, _head2)
        return frame

    async def _recv_frame_auto(
        self,
        reader: asyncio.StreamReader,
        timeout: float,
        frame_format: str = "3e_binary",
        _head2: bytes | None = None,
    ) -> tuple[bytes, str]:
        """按响应数据长度字段收一帧, 返回 (帧字节, 实际帧格式)。

        响应 = 副头部(D0 00/D4 00 二进制, "D000"/"D400" ASCII) + 路由回显
        + 数据长 + 结束代码 + 数据。数据长: 二进制 2B LE @dl_off, ASCII
        4 字符 hex 文本 @dl_off。frame_format="auto" 时按副头部判别,
        供 probe/send_raw 等无法预知对端格式的场景。
        """
        if _head2 is None:
            _head2 = await recv_exact(reader, 2, timeout)
        if frame_format == "auto":
            frame_format = self._RESP_SUBHEADER_TO_FORMAT.get(_head2)
            if frame_format is None:
                raise ProtocolError(
                    f"unrecognized response subheader {_head2.hex()}, stream out of sync"
                )
        is_ascii = codec._is_ascii(frame_format)
        dl_off = codec._DATALEN_OFFSETS[frame_format]
        head = _head2 + await recv_exact(reader, dl_off + (2 if is_ascii else 0), timeout)
        expected_sub = codec._RESP_SUBHEADERS[frame_format]
        if is_ascii:
            if head[:2] not in (b"D0", b"D4") or int(head[:2] + b"00", 16) != expected_sub:
                raise ProtocolError(
                    f"bad {frame_format} response subheader {head[:4]!r}, stream out of sync"
                )
            data_len = int(head[dl_off:dl_off + 4], 16)
        else:
            (sub,) = struct.unpack_from(">H", head, 0)
            if sub != expected_sub:
                raise ProtocolError(
                    f"bad {frame_format} response subheader {sub:#06x} (expected {expected_sub:#06x}), stream out of sync"
                )
            (data_len,) = struct.unpack_from("<H", head, dl_off)
        # ASCII 数据长按字符计 (结束码 4 字符 + 每字 4 字符), 上限放宽一倍
        if not 2 <= data_len <= (0x4000 if is_ascii else 0x2000):
            raise ProtocolError(f"implausible {frame_format} data_length {data_len}, aborting read")
        payload = await recv_exact(reader, data_len, timeout)
        return head + payload, frame_format

    # ------------------------------------------------------------ probe

    async def probe(self, target: Target) -> ProbeResult:
        """probe 不走连接池 (与 Modbus/FINS 同理): 一次性连接读 D0 两个字。

        请求格式依次尝试 3E binary (行业默认) 与 3E ASCII (设备配置为
        ASCII 通信时 binary 请求可能被静默丢弃或回数据代码错误); 响应副
        头部自动判别。取最优结果: 正常完成 > 异常响应 (在线且回规范异常
        帧, P3 语义) > 无响应。
        """
        results = [await self._probe_once(target, "3e_binary")]
        if self._probe_rank(results[0]) == 2:  # 正常完成, 无需 ASCII 回退
            return results[0]
        results.append(await self._probe_once(target, "3e_ascii"))
        return max(results, key=self._probe_rank)

    @staticmethod
    def _probe_rank(r: ProbeResult) -> int:
        if r.reachable and r.failure_class is None:
            return 2  # 正常完成
        if r.reachable:  # exception_response
            return 1
        return 0  # connected_but_no_reply / connection_refused / timeout

    async def _probe_once(self, target: Target, request_format: str) -> ProbeResult:
        timeout = self.timeout(None)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout
            )
        except ConnectionRefusedError:
            return ProbeResult(reachable=False, failure_class="connection_refused", layer_hint="connectivity")
        except TimeoutError:
            return ProbeResult(reachable=False, failure_class="timeout", layer_hint="connectivity")
        except OSError:
            return ProbeResult(reachable=False, failure_class="connection_refused", layer_hint="connectivity")
        try:
            # 读 2 字: 部分从站实现 (如开源 plc-simulator) 对 1 字读有越界 bug
            request = codec.build_read_request("D", 0, 2, frame_format=request_format)
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout)
            resp, resp_format = await self._recv_frame_auto(reader, timeout, frame_format="auto")
        except (ProtocolError, TimeoutError, asyncio.IncompleteReadError, OSError, ConnectionError):
            # TCP 已建立但没完成一次完整协议交互
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")
        finally:
            writer.close()
        parsed = codec.parse_response_fmt(resp, request=request, frame_format=resp_format)
        end_field = next((f for f in parsed.fields if f.name == "end_code"), None)
        if end_field is None or not parsed.valid:
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")
        end_code = end_field.value
        if isinstance(end_code, int) and end_code != 0:
            return ProbeResult(
                reachable=True,
                failure_class="exception_response",
                exception_code=end_code,
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
        device: str = "D",
        frame_format: str = "3e_binary",
    ) -> ReadResult:
        """读软元件 (0401 批量读, 字单位)。

        device: D/R/W 为字软元件; X/Y/B/M 为位软元件 (按字读, 每字 16 点,
        字节序无意义)。byteorder 语义: MC 线上数据是小端, codec 解出的
        word_values 已按小端成 16 位整数; datatype=float32 时 little =
        低字在前 (MC 原生), big = 高字在前 (多数组态软件导出顺序)。
        默认 big 与 Modbus 工具语义对齐。
        """
        timeout = self.timeout(timeout_ms)
        request = codec.build_read_request(device, address, count, frame_format=frame_format)
        started = time.perf_counter()
        resp = await locked_exchange(
            self.pool, self.key_for(target), request,
            functools.partial(self._recv_frame, frame_format=frame_format), timeout,
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        parsed = codec.parse_response_fmt(resp, request=request, frame_format=frame_format)
        end_field = next((f for f in parsed.fields if f.name == "end_code"), None)
        if end_field is None:
            raise McError("malformed response: no end code found; " + "; ".join(parsed.errors))
        end_code = end_field.value
        if isinstance(end_code, int) and end_code != 0:
            raise McError(
                f"device returned end code {codec.end_code_name(end_code)} ({end_code:#06x})"
                f" for device {device} head={address} count={count}"
            )
        if not parsed.valid:
            raise McError("malformed response: " + "; ".join(parsed.errors))
        values_field = next(f for f in parsed.fields if f.name == "word_values")
        raw = list(values_field.value)  # type: ignore[arg-type]
        expected_words = (count + 15) // 16 if device in codec.BIT_DEVICES else count
        if len(raw) < expected_words:
            raise McError(f"device returned {len(raw)} words, requested {expected_words}")
        interpreted = codec.interpret_registers(raw, datatype, byteorder)
        return ReadResult(
            target=target,
            address=address,
            request_frame=request.hex(),
            raw_registers=raw,
            interpreted=interpreted,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------ write

    async def write(
        self,
        target: Target,
        address: int,
        values: list[int],
        *,
        on_frame: "Callable[[str], None] | None" = None,
        point_type: str = "register",
        timeout_ms: int | None = None,
        **options,
    ) -> dict:
        """批量写 (1401, 字单位)。

        options: device (默认 D, 字软元件 D/R/W; 位软元件按打包字写),
        frame_format (默认 3e_binary), timer。
        point_type 仅接受 "register" (MC 无线圈/寄存器之分)。
        """
        if point_type != "register":
            raise ValueError(
                f"melsec write only supports point_type='register' (word units), got {point_type!r}"
            )
        timeout = self.timeout(timeout_ms)
        device = options.get("device", "D")
        frame_format = options.get("frame_format", "3e_binary")
        timer = options.get("timer", 4)
        request = codec.build_write_request(
            device, address, values, timer=timer, frame_format=frame_format
        )
        if on_frame is not None:
            on_frame(request.hex())  # 审计红线: 发送前留痕, 失败也留
        started = time.perf_counter()
        resp = await locked_exchange(
            self.pool, self.key_for(target), request,
            functools.partial(self._recv_frame, frame_format=frame_format), timeout,
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        parsed = codec.parse_response_fmt(resp, request=request, frame_format=frame_format)
        end_field = next((f for f in parsed.fields if f.name == "end_code"), None)
        if end_field is None:
            raise McError("malformed response: no end code found; " + "; ".join(parsed.errors))
        end_code = end_field.value
        if isinstance(end_code, int) and end_code != 0:
            raise McError(
                f"device returned end code {codec.end_code_name(end_code)} ({end_code:#06x})"
                f" for device {device} head={address} count={len(values)}"
            )
        if not parsed.valid:
            raise McError("malformed response: " + "; ".join(parsed.errors))
        return {
            "request_frame": request.hex(),
            "response_frame": resp.hex(),
            "elapsed_ms": elapsed_ms,
        }

    # ------------------------------------------------------------ send_raw

    async def send_raw(
        self, target: Target, frame_hex: str, timeout_ms: int | None = None
    ) -> RawExchange:
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        resp = await locked_exchange(
            self.pool, self.key_for(target), frame,
            functools.partial(self._recv_frame, frame_format="auto"), timeout,
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RawExchange(
            target=target, sent_frame=frame.hex(), received_frame=resp.hex(), elapsed_ms=elapsed_ms
        )


class McError(ProtocolError):
    """MELSEC 设备错误 (结束代码非 0 / 畸形响应)。"""
