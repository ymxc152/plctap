"""IEC 60870-5-104 适配器 (v0.5.2): probe / read (总召收集) / send_raw。

104 是主从+序号协议: 连接持有 I 帧收发序号状态, 因此读写走连接池
(与 FINS 会话同理), 序号存在 conn.metadata 里跨调用保持。

probe 刻意不走连接池: 一次性连接 STARTDT_ACT -> 期待 STARTDT_CON
(+TESTFR), 即用即关。reachable 语义 = 传输层可达 + U 格式握手指纹。

read 用 C_IC_NA_1 总召收集 (COT=ACT -> ACT_CON -> 监视帧 -> ACT_TERM):
绝大多数 RTU/远动设备不支持 C_RD_NA_1 单点读, 总召是唯一通用读路径;
count = 连续 IOA 点数 (M_ME_NC 每点 2 个 16 位字, 拆字顺序按大端字序
返回, 与 float32 解释器的 ABCD 语义对齐)。
"""

from __future__ import annotations

import asyncio
import struct
import time

from plctap.models import (
    ByteOrder,
    ProbeResult,
    RawExchange,
    ReadResult,
    Target,
)
from plctap.protocols import base
from plctap.protocols.base import ProtocolAdapter, ProtocolError, register_adapter
from plctap.protocols.iec104 import codec
from plctap.protocols.iec104 import meta as _meta

_W_WINDOW = 8  # 未确认 I 帧数超过 w 发 S 帧 (默认 k=12/w=8)


@register_adapter
class Iec104Adapter(ProtocolAdapter):
    name = "iec104"
    meta = _meta.META

    # ------------------------------------------------------------ 收帧

    async def _recv_apdu(self, reader: asyncio.StreamReader, timeout: float) -> bytes:
        """按 APDU 长度字段收一帧 (len 字段含 4B 控制域, 总帧长 = 2 + len)。"""
        head = await base.recv_exact(reader, 2, timeout)
        if head[0] != codec.START_BYTE:
            raise ProtocolError(
                f"bad APCI start byte {head[0]:#04x} (expected 0x68), stream out of sync"
            )
        apdu_len = head[1]
        if not codec.MIN_APDU_LEN <= apdu_len <= codec.MAX_APDU_LEN:
            raise ProtocolError(f"implausible APDU length {apdu_len}, aborting read")
        rest = await base.recv_exact(reader, apdu_len, timeout)
        return head + rest

    # ------------------------------------------------------------ probe

    async def probe(self, target: Target) -> ProbeResult:
        timeout = self.timeout(None)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout
            )
        except (ConnectionRefusedError, OSError):
            return ProbeResult(reachable=False, failure_class="connection_refused",
                               layer_hint="connectivity")
        except TimeoutError:
            return ProbeResult(reachable=False, failure_class="timeout",
                               layer_hint="connectivity")
        try:
            writer.write(codec.build_apci_u(codec.U_STARTDT_ACT))
            await asyncio.wait_for(writer.drain(), timeout)
            con = await self._recv_apdu(reader, timeout)
            if not (len(con) == 6 and con[2] == codec.U_STARTDT_CON):
                return ProbeResult(reachable=False, failure_class="connected_but_no_reply",
                                   layer_hint="protocol")
            writer.write(codec.build_apci_u(codec.U_TESTFR_ACT))
            await asyncio.wait_for(writer.drain(), timeout)
            con = await self._recv_apdu(reader, timeout)
            if not (len(con) == 6 and con[2] == codec.U_TESTFR_CON):
                return ProbeResult(reachable=False, failure_class="connected_but_no_reply",
                                   layer_hint="protocol")
        except (ProtocolError, TimeoutError, asyncio.IncompleteReadError, OSError, ConnectionError):
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply",
                               layer_hint="protocol")
        finally:
            writer.close()
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
        **options,
    ) -> ReadResult:
        """总召收集读: C_IC_NA_1 激活 -> 收监视帧 -> ACT_TERM。

        count = 连续 IOA 点数。返回 raw_registers: 遥信/归一化/标度化
        每点 1 个 16 位字, 短浮点每点 2 字 (高字在前, float32 big 解释
        直接可用); 点值缺漏以 None 占位并记 interpreted_note。
        """
        if count < 1:
            raise ValueError("count must be >= 1")
        ca = options.get("ca", 1)
        qoi = options.get("qoi", 20)
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            conn = await self.pool.acquire(key, timeout)
            try:
                request, values, notes = await self._interrogate(
                    conn, target, ca, qoi, address, count, timeout
                )
            except ProtocolError:
                self.pool.discard(conn)
                raise
            except TimeoutError:
                self.pool.discard(conn)
                raise ProtocolError(f"timeout during interrogation from {key.target}") from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        if not values:
            raise ProtocolError(
                f"interrogation returned no objects for IOA {address}..{address + count - 1}"
            )
        raw: list[int] = []
        present: list[int] = []  # 实际收到的点值 (按 IOA 顺序)
        for ioa in range(address, address + count):
            v = values.get(ioa)
            if v is None:
                raw.extend([0] * v_words(ioa, values))
                notes.append(f"IOA {ioa} missing in interrogation response")
            else:
                raw.extend(v)
                present.extend(v)
        interpreted = _interpret_present(present, datatype, byteorder)
        return ReadResult(
            target=target, address=address, request_frame=request.hex(),
            raw_registers=raw, interpreted=interpreted, elapsed_ms=elapsed_ms,
        )

    async def _interrogate(self, conn, target: Target, ca: int, qoi: int,
                           address: int, count: int, timeout: float):
        """总召会话: 维护 I 帧序号, 收集监视帧值。返回 (请求帧, {ioa: 值字列表}, notes)。"""
        meta = conn.metadata
        tx: int = meta.get("i104_tx", 0)
        rx: int = meta.get("i104_rx", 0)
        notes: list[str] = []
        # I 帧必须发生在 STARTDT 之后 (规范 6.1.4): 池内连接首次使用时启动数据传输
        if not meta.get("i104_started"):
            writer = conn.writer
            writer.write(codec.build_apci_u(codec.U_STARTDT_ACT))
            await asyncio.wait_for(writer.drain(), timeout)
            while True:
                frame = await self._recv_apdu(conn.reader, timeout)
                if codec.apci_format(frame[2:6]) == "U":
                    if frame[2] == codec.U_STARTDT_CON:
                        meta["i104_started"] = True
                        break
                    if frame[2] == codec.U_TESTFR_ACT:
                        writer.write(codec.build_apci_u(codec.U_TESTFR_CON))
                        await asyncio.wait_for(writer.drain(), timeout)
                        continue
                    if frame[2] == codec.U_STOPDT_CON:
                        continue
                    raise ProtocolError(
                        f"unexpected U function {frame[2]:#04x} before STARTDT_CON"
                    )
                raise ProtocolError("I-frame received before STARTDT_CON (server protocol violation)")
        asdu = codec.build_asdu_interrogation(qoi=qoi, ca=ca, cot=6)
        request = codec.build_apci_i(tx, rx, asdu)
        tx = (tx + 1) & 0x7FFF
        conn.writer.write(request)
        await asyncio.wait_for(conn.writer.drain(), timeout)

        values: dict[int, list[int]] = {}
        act_con = False
        act_term = False
        unacked = 0
        while not act_term:
            frame = await self._recv_apdu(conn.reader, timeout)
            fmt = codec.apci_format(frame[2:6])
            if fmt == "U":
                fn = frame[2]
                if fn == codec.U_TESTFR_ACT:  # 服务端测试链路: 回 CON
                    conn.writer.write(codec.build_apci_u(codec.U_TESTFR_CON))
                    await asyncio.wait_for(conn.writer.drain(), timeout)
                continue
            if fmt == "S":
                continue  # 服务端确认我们的发送序号, 无需动作
            # I 帧: 校验接收序号连续性 (跳号 = 丢帧, 诊断引擎素材)
            (_, rseq) = codec.apci_seq_i(frame[2:6])
            expected_rx = (rx + 1) & 0x7FFF
            if rseq != expected_rx:
                notes.append(f"rx_seq jump {rx} -> {rseq} (丢帧或乱序)")
            rx = rseq
            unacked += 1
            parsed = codec.parse_asdu(frame, codec.APCI_LEN, len(frame) - 6)
            if not parsed.valid:
                notes.extend(f"ASDU error: {e}" for e in parsed.errors)
                continue
            fields = {f.name: f.value for f in parsed.fields}
            type_id = fields.get("type_id")
            cot = fields.get("cot")
            if type_id == codec.C_IC_NA_1 and cot == 7:
                act_con = True
                continue
            if type_id == codec.C_IC_NA_1 and cot == 10:
                act_term = True
                continue
            if type_id in codec.MONITOR_TYPES:
                ioas = _parsed_ioas(parsed)
                vals = fields.get("asdu_values", [])
                per = _words_per_point(type_id)
                _collect(values, ioas, vals, per)
            if unacked >= _W_WINDOW:
                conn.writer.write(codec.build_apci_s(rx))
                await asyncio.wait_for(conn.writer.drain(), timeout)
                unacked = 0
        if not act_con:
            notes.append("总召未收到 ACT_CON")
        meta["i104_tx"] = tx
        meta["i104_rx"] = rx
        return request, values, notes

    # ------------------------------------------------------------ send_raw

    async def send_raw(
        self, target: Target, frame_hex: str, timeout_ms: int | None = None
    ) -> RawExchange:
        """发送原始帧并等待一帧响应 (不经连接池: 序号状态无法与池内连接共享)。"""
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout
            )
            writer.write(frame)
            await asyncio.wait_for(writer.drain(), timeout)
            resp = await self._recv_apdu(reader, timeout)
        except TimeoutError:
            raise ProtocolError(f"timeout waiting for response from {target}") from None
        finally:
            if writer is not None:
                writer.close()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RawExchange(target=target, sent_frame=frame.hex(),
                           received_frame=resp.hex(), elapsed_ms=elapsed_ms)


# ------------------------------------------------------------ 辅助 (纯函数)


def v_words(ioa: int, values: dict[int, list[int]]) -> int:
    """缺漏点占位字数 (按相邻点宽度推断, 无相邻按 1)。"""
    for d in (1, -1, 2, -2):
        v = values.get(ioa + d)
        if v is not None:
            return len(v)
    return 1


def _parsed_ioas(parsed) -> list[int]:
    return [f.value for f in parsed.fields if f.name.endswith("_ioa") and isinstance(f.value, int)]


def _words_per_point(type_id: int) -> int:
    return 2 if type_id in (13, 36) else 1


def _collect(values: dict[int, list[int]], ioas: list[int], vals: list[int], per: int) -> None:
    """按每点字数把扁平值列表分配到各 IOA (短浮点 wire LE -> [高字, 低字])。"""
    if per == 2:
        pairs = [(vals[i], vals[i + 1]) for i in range(0, len(vals) - 1, 2)]
        for ioa, pair in zip(ioas, pairs):
            values[ioa] = list(pair)  # [高字, 低字] (codec 解出时已转大端字序)
    else:
        for ioa, v in zip(ioas, vals):
            values[ioa] = [v]


def _interpret_present(present: list[int], datatype: str | None, byteorder: ByteOrder) -> list:
    """只解释实际收到的点值 (缺漏点以 0 占位在 raw 中, notes 里说明)。"""
    if not present:
        return []
    if datatype is None:
        return present
    return codec.interpret_registers(present, datatype, byteorder)
