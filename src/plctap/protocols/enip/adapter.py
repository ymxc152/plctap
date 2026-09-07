"""EtherNet/IP (CIP) 适配器 (v0.5.3): probe=ListIdentity, read/write=非连接 tag 读写。

ENIP 是会话协议 (RegisterSession 换 session handle), 会话随池内连接保持
(metadata["enip_session"]); tag 名是字符串, 与其余协议的整数地址不同 ——
server 层对 enip 传入 str 地址。

probe 刻意不走连接池: ListIdentity 无需会话, 一次连接即取设备身份
(vendor/product_name), 还能反哺 detect 的 vendor 识别。
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
from plctap.protocols.enip import codec
from plctap.protocols.enip import meta as _meta


@register_adapter
class EnipAdapter(ProtocolAdapter):
    name = "enip"
    meta = _meta.META

    # ------------------------------------------------------------ 收帧

    async def _recv_enip(self, reader: asyncio.StreamReader, timeout: float) -> bytes:
        """按封装头长度字段收一帧 (24B 头 + length 载荷)。"""
        head = await base.recv_exact(reader, codec.ENIP_HEADER_LEN, timeout)
        command, length, _session, _status = struct.unpack_from("<HHII", head, 0)
        if command not in codec.COMMAND_NAMES:
            raise ProtocolError(f"unknown ENIP command {command:#06x}, stream out of sync")
        if not 0 <= length <= 0xFFFF:
            raise ProtocolError(f"implausible ENIP payload length {length}, aborting read")
        payload = await base.recv_exact(reader, length, timeout)
        return head + payload

    # ------------------------------------------------------------ 会话

    async def _ensure_session(self, conn, timeout: float) -> int:
        """池内连接首次使用时 RegisterSession, 句柄存 metadata 跨调用复用。"""
        session = conn.metadata.get("enip_session")
        if session:
            return session
        conn.writer.write(codec.build_register_session())
        await asyncio.wait_for(conn.writer.drain(), timeout)
        resp = await self._recv_enip(conn.reader, timeout)
        handle = codec.parse_register_session_response(resp)
        conn.metadata["enip_session"] = handle
        return handle

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
            writer.write(codec.build_list_identity())
            await asyncio.wait_for(writer.drain(), timeout)
            resp = await self._recv_enip(reader, timeout)
            identity = codec.parse_list_identity_response(resp)
        except (ProtocolError, TimeoutError, asyncio.IncompleteReadError, OSError, ConnectionError, ValueError):
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply",
                               layer_hint="protocol")
        finally:
            writer.close()
        return ProbeResult(reachable=True, layer_hint="application",
                           identity={
                               "vendor_id": identity.get("vendor_id"),
                               "product_name": identity.get("product_name"),
                               "product_code": identity.get("product_code"),
                           })

    # ------------------------------------------------------------ read

    async def read(
        self,
        target: Target,
        address,
        count: int,
        datatype: str | None = None,
        byteorder: ByteOrder = "little",
        timeout_ms: int | None = None,
        **options,
    ) -> ReadResult:
        """读 tag (CIP 0x4C 非连接读)。

        address = tag 名字符串 ("alpha" 或 "alpha[0]"); count = 元素数。
        原始 16 位字序列按类型的字宽解释 (DINT 每元素 2 字, REAL 每元素
        2 字); datatype 缺省按 ENIP 类型码返回 int16 字值, float32/DINT
        由 interpret 层合并。
        """
        if not isinstance(address, str):
            raise ValueError(
                f"enip address must be a tag name string (e.g. 'alpha[0]'), got {address!r}"
            )
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            conn = await self.pool.acquire(key, timeout)
            try:
                session = await self._ensure_session(conn, timeout)
                request = codec.build_send_rr_data(
                    session, codec.build_unconnected_send(codec.build_read_tag(address, count))
                )
                conn.writer.write(request)
                await asyncio.wait_for(conn.writer.drain(), timeout)
                resp = await self._recv_enip(conn.reader, timeout)
            except ProtocolError:
                self.pool.discard(conn)
                raise
            except TimeoutError:
                self.pool.discard(conn)
                raise ProtocolError(f"timeout waiting for tag read from {key.target}") from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        cip, _ = codec.parse_cip_reply_from_rrdata(resp)
        parsed = codec.parse_tag_reply(cip, codec.SVC_READ_TAG)
        fields = {f.name: f.value for f in parsed.fields}
        if not parsed.valid:
            raise ProtocolError(
                f"tag read failed: {'; '.join(parsed.errors)} for tag {address!r} count={count}"
            )
        type_code = fields.get("data_type")
        type_name = codec.TYPE_CODES.get(type_code, ("UNKNOWN", 1))[0]
        raw = list(fields.get("word_values", []))
        expected_words = count * codec.TYPE_CODES[type_code][1]
        if len(raw) < expected_words:
            raise ProtocolError(f"tag returned {len(raw)} words, expected {expected_words}")
        interpreted = _interpret_enip(raw, type_code, count, datatype, byteorder)
        return ReadResult(
            target=target, address=address, request_frame=resp.hex(),
            raw_registers=raw, interpreted=interpreted,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------ write

    async def write(
        self,
        target: Target,
        address,
        values: list[int],
        *,
        on_frame=None,
        point_type: str = "tag",
        timeout_ms: int | None = None,
        **options,
    ) -> dict:
        """写 tag (CIP 0x4D)。values 为 16 位字序列; 整数按 DINT (2 字),
        浮点按 REAL (2 字) —— 类型码由 options.type 或值域推断。"""
        if not isinstance(address, str):
            raise ValueError(f"enip address must be a tag name string, got {address!r}")
        timeout = self.timeout(timeout_ms)
        type_code = options.get("type")
        if type_code is None:
            # 值域推断: 任一值超 16 位字域或非整 -> REAL? 保守: 全 int 且每值 <=0xFFFF 且单字宽 -> INT?
            # 默认 DINT (Logix 最通用), 浮点需显式 options.type="REAL"
            type_code = 0xC4
        if isinstance(type_code, str):
            name = type_code.upper()
            type_code = next((c for c, (n, _) in codec.TYPE_CODES.items() if n == name), None)
            if type_code is None:
                raise ValueError(f"unknown ENIP type name {options.get('type')!r}")
        _, words_per = codec.TYPE_CODES[type_code]
        payload_words: list[int] = []
        for v in values:
            payload_words.extend(_pack_value_words(v, words_per))
        key = self.key_for(target)
        started = time.perf_counter()
        async with self.pool.lock_for(key):
            conn = await self.pool.acquire(key, timeout)
            try:
                session = await self._ensure_session(conn, timeout)
                request = codec.build_send_rr_data(
                    session,
                    codec.build_unconnected_send(
                        codec.build_write_tag(address, type_code, payload_words)
                    ),
                )
                if on_frame is not None:
                    on_frame(request.hex())
                conn.writer.write(request)
                await asyncio.wait_for(conn.writer.drain(), timeout)
                resp = await self._recv_enip(conn.reader, timeout)
            except ProtocolError:
                self.pool.discard(conn)
                raise
            except TimeoutError:
                self.pool.discard(conn)
                raise ProtocolError(f"timeout waiting for tag write from {key.target}") from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        cip, _ = codec.parse_cip_reply_from_rrdata(resp)
        parsed = codec.parse_tag_reply(cip, codec.SVC_WRITE_TAG)
        if not parsed.valid:
            raise ProtocolError(f"tag write failed: {'; '.join(parsed.errors)} for tag {address!r}")
        return {
            "request_frame": request.hex(),
            "response_frame": resp.hex(),
            "elapsed_ms": elapsed_ms,
        }

    # ------------------------------------------------------------ send_raw

    async def send_raw(
        self, target: Target, frame_hex: str, timeout_ms: int | None = None
    ) -> RawExchange:
        """发送任意 ENIP 帧并等待一帧响应 (不经连接池, 无会话状态)。"""
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
            resp = await self._recv_enip(reader, timeout)
        except TimeoutError:
            raise ProtocolError(f"timeout waiting for response from {target}") from None
        finally:
            if writer is not None:
                writer.close()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RawExchange(target=target, sent_frame=frame.hex(),
                           received_frame=resp.hex(), elapsed_ms=elapsed_ms)


# ------------------------------------------------------------ 辅助 (纯函数)


def _pack_value_words(v: int, words_per: int) -> list[int]:
    """值 -> 16 位字序列 (小端拆字, CIP 数据区原生 LE)。"""
    v = v & 0xFFFFFFFF if words_per <= 2 else v & 0xFFFFFFFFFFFFFFFF
    return [struct.unpack_from("<H", struct.pack("<I", v), 2 * i)[0] for i in range(words_per)]


def _interpret_enip(raw: list[int], type_code: int, count: int,
                    datatype: str | None, byteorder: ByteOrder) -> list:
    """按 ENIP 类型码把字序列解释成元素值。

    BOOL/SINT/INT: 每元素 1 字 -> int; DINT/REAL: 每元素 2 字
    (CIP 数据区 LE -> [低字, 高字], 解释时合并为 32 位)。
    datatype=float32 只对 REAL 生效 (byteorder 忽略, ENIP 原生小端);
    datatype=dint 对 DINT 合并 32 位有符号。
    """
    name, _ = codec.TYPE_CODES[type_code]
    if name in ("BOOL", "SINT", "INT"):
        vals = raw[:count]
        if name == "BOOL":
            return [v & 1 for v in vals]
        if datatype is None:
            return vals
        return [v - 0x10000 if v & 0x8000 else v for v in vals]
    # 32 位: 每元素 [低字, 高字] -> 32 位
    out = []
    for i in range(min(count, len(raw) // 2)):
        lo, hi = raw[2 * i], raw[2 * i + 1]
        bits = lo | (hi << 16)
        if datatype == "float32" and name == "REAL":
            out.append(struct.unpack("<f", struct.pack("<I", bits))[0])
        elif datatype in ("dint", "int32") or (datatype is None and name == "DINT"):
            out.append(bits - 0x100000000 if bits & 0x80000000 else bits)
        elif datatype is None:
            out.append(bits)
        else:
            out.append(bits)
    return out
