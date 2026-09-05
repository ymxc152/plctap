"""Siemens S7comm 适配器: 有状态连接 (COTP + PDU 协商) + probe/read/write。

与 FINS 同理: 握手状态挂 conn.metadata, 每连接一次。
S7 连接序列: TCP -> COTP CR -> CC -> PDU Negotiation -> 可读写。
"""

from __future__ import annotations

import asyncio
import struct
import time
import itertools

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
    recv_exact,
    register_adapter,
)
from plctap.protocols.s7 import codec
from plctap.protocols.s7 import meta as _meta

_pdu_ref_counter = itertools.count(1)


@register_adapter
class S7Adapter(ProtocolAdapter):
    name = "s7"
    meta = _meta.META

    # ------------------------------------------------------------ 帧收发

    async def _recv_tpkt(self, reader: asyncio.StreamReader, timeout: float) -> bytes:
        """按 TPKT 长度字段收完整帧。"""
        header = await recv_exact(reader, 4, timeout)
        if header[0] != 3:
            raise ProtocolError(f"bad TPKT version {header[0]}, stream out of sync")
        (total_len,) = struct.unpack_from(">H", header, 2)
        if total_len < 7 or total_len > 0xFFFF:
            raise ProtocolError(f"implausible TPKT length {total_len}")
        payload = await recv_exact(reader, total_len - 4, timeout)
        return header + payload

    # ------------------------------------------------------------ 握手

    async def _ensure_handshake(self, conn, target: Target, timeout: float, rack: int = 0, slot: int = 1) -> None:
        """COTP Connect + PDU Negotiation: 每连接一次。"""
        if conn.metadata.get("s7_handshaked"):
            return

        # Step 1: COTP Connection Request
        cr = codec.build_cotp_connect_request(rack, slot)
        conn.writer.write(cr)
        await asyncio.wait_for(conn.writer.drain(), timeout)
        cc = await self._recv_tpkt(conn.reader, timeout)
        try:
            codec.parse_cotp_connect_response(cc)
        except ValueError as e:
            self.pool.discard(conn)
            raise ProtocolError(f"S7 COTP connect failed: {e}") from e

        # Step 2: PDU Negotiation
        neg = codec.build_pdu_negotiation(480)
        conn.writer.write(neg)
        await asyncio.wait_for(conn.writer.drain(), timeout)
        neg_resp = await self._recv_tpkt(conn.reader, timeout)
        try:
            pdu_len = codec.parse_pdu_negotiation_response(neg_resp, 480)
        except ValueError as e:
            self.pool.discard(conn)
            raise ProtocolError(f"S7 PDU negotiation failed: {e}") from e

        conn.metadata["s7_handshaked"] = True
        conn.metadata["s7_pdu_length"] = pdu_len

    # ------------------------------------------------------------ 通用交换

    async def _exchange(
        self, target: Target, build_fn, timeout: float,
        rack: int = 0, slot: int = 1,
    ) -> tuple[bytes, bytes]:
        """锁内: 取连接 -> (按需)握手 -> 构建 -> 发送 -> 收帧 -> 归还。"""
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            conn = await self.pool.acquire(key, timeout)
            try:
                await self._ensure_handshake(conn, target, timeout, rack, slot)
                request = build_fn(next(_pdu_ref_counter))
                conn.writer.write(request)
                await asyncio.wait_for(conn.writer.drain(), timeout)
                resp = await self._recv_tpkt(conn.reader, timeout)
            except ProtocolError:
                self.pool.discard(conn)
                raise
            except TimeoutError:
                self.pool.discard(conn)
                raise ProtocolError(f"timeout waiting for response from {key.target}") from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)
                return request, resp

    # ------------------------------------------------------------ probe

    async def probe(self, target: Target) -> ProbeResult:
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
            # Handshake
            cr = codec.build_cotp_connect_request(0, 1)
            writer.write(cr)
            await asyncio.wait_for(writer.drain(), timeout)
            cc = await self._recv_tpkt(reader, timeout)
            codec.parse_cotp_connect_response(cc)

            neg = codec.build_pdu_negotiation(480)
            writer.write(neg)
            await asyncio.wait_for(writer.drain(), timeout)
            neg_resp = await self._recv_tpkt(reader, timeout)
            codec.parse_pdu_negotiation_response(neg_resp, 480)

            # Read DB1.DBX0.0 (1 word)
            pdu_ref = next(_pdu_ref_counter)
            request = codec.build_read_request("DB", 1, 0, 2, pdu_ref)
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout)
            resp = await self._recv_tpkt(reader, timeout)
        except (ProtocolError, TimeoutError, asyncio.IncompleteReadError, OSError, ConnectionError):
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")
        finally:
            writer.close()

        try:
            parsed = codec.parse_read_response(resp, request=request)
            rc_field = next((f for f in parsed.fields if f.name == "return_code"), None)
            if rc_field is None or not parsed.valid:
                return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")
            rc = rc_field.value
            if isinstance(rc, int) and rc != 0xFF:
                return ProbeResult(reachable=True, failure_class="exception_response", exception_code=rc, layer_hint="application")
            return ProbeResult(reachable=True, layer_hint="application")
        except ValueError:
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")

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
        timeout = self.timeout(timeout_ms)
        area = options.get("area", "DB")
        db_number = options.get("db_number", 1)
        rack = options.get("rack", 0)
        slot = options.get("slot", 1)

        transport_size = codec.TS_BYTE
        request, resp = await self._exchange(
            target,
            lambda ref: codec.build_read_request(area, db_number, address, count, ref, transport_size),
            timeout, rack, slot,
        )
        elapsed_ms = int((time.perf_counter() - asyncio.get_event_loop().time()) * 1000)

        parsed = codec.parse_read_response(resp, request=request)
        rc_field = next((f for f in parsed.fields if f.name == "return_code"), None)
        if rc_field is None:
            raise S7Error("malformed response: no return code; " + "; ".join(parsed.errors))
        rc = rc_field.value
        if isinstance(rc, int) and rc != 0xFF:
            raise S7Error(f"S7 return code {codec.return_code_name(rc)} ({rc:#04x}) for area={area} db={db_number} start={address} count={count}")
        if not parsed.valid:
            raise S7Error("malformed response: " + "; ".join(parsed.errors))

        values_field = next((f for f in parsed.fields if f.name == "word_values"), None)
        raw = list(values_field.value) if values_field else []
        interpreted = codec.interpret_registers(raw, datatype, byteorder)
        return ReadResult(
            target=target, address=address, request_frame=request.hex(),
            raw_registers=raw, interpreted=interpreted, elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------ write

    async def write(
        self, target: Target, address: int, values: list[int], **options
    ) -> dict:
        timeout = self.timeout(options.get("timeout_ms"))
        area = options.get("area", "DB")
        db_number = options.get("db_number", 1)
        rack = options.get("rack", 0)
        slot = options.get("slot", 1)

        pdu_ref = next(_pdu_ref_counter)
        request = codec.build_write_request(area, db_number, address, values, pdu_ref)
        started = time.perf_counter()

        async with self.pool.lock_for(self.key_for(target)):
            conn = await self.pool.acquire(self.key_for(target), timeout)
            try:
                await self._ensure_handshake(conn, target, timeout, rack, slot)
                conn.writer.write(request)
                await asyncio.wait_for(conn.writer.drain(), timeout)
                resp = await self._recv_tpkt(conn.reader, timeout)
            except ProtocolError:
                self.pool.discard(conn)
                raise
            except TimeoutError:
                self.pool.discard(conn)
                raise ProtocolError(f"timeout waiting for write response from {self.key_for(target).target}") from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        result = codec.parse_write_response(resp, request=request)
        if not result["ok"]:
            rc = result["return_code"]
            raise S7Error(f"S7 write failed: return code {codec.return_code_name(rc)} ({rc:#04x})")
        return {"request_frame": request.hex(), "response_frame": resp.hex(), "elapsed_ms": elapsed_ms}

    # ------------------------------------------------------------ send_raw

    async def send_raw(self, target: Target, frame_hex: str, timeout_ms: int | None = None) -> RawExchange:
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        request, resp = await self._exchange(target, lambda _: frame, timeout)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RawExchange(target=target, sent_frame=frame.hex(), received_frame=resp.hex(), elapsed_ms=elapsed_ms)


class S7Error(ProtocolError):
    """S7 设备错误 (return code 非 0xFF / 畸形响应)。"""
