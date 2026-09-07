"""EtherNet/IP (CIP) 适配器测试: 进程内 fake ENIP server (RegisterSession/
ListIdentity/0x4C 读/0x4D 写/未知 tag CIP 0x05)。"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator

import pytest

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
from plctap.protocols.enip import codec
from plctap.protocols.enip.adapter import EnipAdapter, ProtocolError


class FakeEnipServer:
    """ENIP 假服务器: 标准封装 + 0xB2 请求项, 罐头 tag:
    alpha = DINT[3] = [42, 43, 44]; beta = REAL[2] = [0.25, 0.5]。
    mode: normal / silent / unknown_tag(所有读回 0x05)。
    """

    def __init__(self, mode: str = "normal") -> None:
        self.mode = mode
        self._server: asyncio.Server | None = None
        self._abort = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()
        self.stored: dict[str, list[int]] = {}

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        return "127.0.0.1", self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._abort.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for w in list(self._writers):
            w.close()

    async def _recv(self, reader: asyncio.StreamReader) -> bytes | None:
        try:
            head = await asyncio.wait_for(reader.readexactly(24), 0.5)
        except (TimeoutError, asyncio.IncompleteReadError):
            return None
        cmd, ln = struct.unpack_from("<HH", head, 0)
        if cmd not in (0x0063, 0x0065, 0x0066, 0x006F, 0x0070):
            return None
        return head + await asyncio.wait_for(reader.readexactly(ln), 1.0)

    @staticmethod
    def _ident() -> bytes:
        ident = (
            struct.pack("<H", 1) + b"\x00" * 16
            + struct.pack("<I", 1) + struct.pack("<H", 12) + struct.pack("<H", 66)
            + bytes([1, 5]) + struct.pack("<H", 0) + struct.pack("<I", 0xC0FFEE)
            + bytes([14]) + b"plctap-fixture"
        )
        return struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(ident)) + ident

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session = 0x1000
        try:
            while not self._abort.is_set():
                frame = await self._recv(reader)
                if frame is None:
                    continue
                (cmd, _ln, _ses, _st, off) = codec.parse_enip_header(frame)
                if self.mode == "silent":
                    continue  # 静默: 对任何请求 (含 ListIdentity) 都不回话
                if cmd == codec.CMD_REGISTER_SESSION:
                    writer.write(codec.build_enip(
                        codec.CMD_REGISTER_SESSION, frame[off:], session=session))
                    await writer.drain()
                elif cmd == codec.CMD_LIST_IDENTITY:
                    writer.write(codec.build_enip(codec.CMD_LIST_IDENTITY, self._ident(),
                                                  session=session))
                    await writer.drain()
                elif cmd == codec.CMD_SEND_RR_DATA:
                    resp = self._handle_rrdata(frame, off)
                    writer.write(codec.build_send_rr_data(session, resp, reply=True))
                    await writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError, ValueError):
            pass
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()

    def _handle_rrdata(self, frame: bytes, off: int) -> bytes:
        (_iface, _timeout, nitems) = struct.unpack_from("<IHH", frame, off)
        if nitems != 2:
            raise ValueError("items")
        o = off + 8
        _addr_type, addr_len = struct.unpack_from("<HH", frame, o)
        o += 4 + addr_len
        _data_type, data_len = struct.unpack_from("<HH", frame, o)
        o += 4
        cip = frame[o:o + data_len]
        # 解 0x52 非连接信封: 嵌入请求 = 真正的 0x4C/0x4D 服务
        if cip[0] == codec.SVC_UNCONNECTED_SEND:
            (elen,) = struct.unpack_from("<H", cip, 1)
            cip = cip[3:3 + elen]
        service = cip[0]
        # 解 tag 路径: service + 路径字长 + 路径 + 参数
        pw = cip[1]
        path = cip[2:2 + pw * 2]
        name_len = path[1]
        name = path[2:2 + name_len].decode("ascii", errors="replace")
        if self.mode == "unknown_tag" or not name.startswith(("alpha", "beta")):
            return bytes([service | 0x80, 0x00, 0x05, 0x00, 0x00])  # CIP 0x05
        if service == codec.SVC_READ_TAG:
            (count,) = struct.unpack_from("<H", cip, 2 + pw * 2)
            if name.startswith("alpha"):
                data = b"".join(struct.pack("<I", 42 + i) for i in range(count))  # DINT 32 位
                return (bytes([0xCC, 0x00, 0x00, 0x00])
                        + struct.pack("<H", 0xC4) + data)
            data = b""
            for i in range(count):
                bits = struct.unpack("<I", struct.pack("<f", 0.25 * (i + 1)))[0]
                data += struct.pack("<HH", bits & 0xFFFF, bits >> 16)
            return (bytes([0xCC, 0x00, 0x00, 0x00])
                    + struct.pack("<H", 0xCA) + data)
        # 0x4D 写: 数据 = 类型 u16 + 元素数 u16 + 字
        (type_code, count) = struct.unpack_from("<HH", cip, 2 + pw * 2)
        bytes_per = 4 if type_code in (0xC4, 0xCA) else 2
        data = cip[2 + pw * 2 + 4:2 + pw * 2 + 4 + count * bytes_per]
        if type_code in (0xC4, 0xCA):  # DINT/REAL: 32 位元素
            self.stored[name] = list(struct.unpack(f"<{count}I", data))
        else:
            self.stored[name] = list(struct.unpack(f"<{count}H", data))
        return bytes([service | 0x80, 0x00, 0x00, 0x00])


@pytest.fixture
async def enip_server() -> AsyncIterator[FakeEnipServer]:
    s = FakeEnipServer()
    s.addr = await s.start()
    yield s
    await s.stop()


def make_adapter(host: str, port: int):
    pool = ConnectionPool(idle_timeout_sec=5.0)
    config = PlctapConfig(default_timeout_ms=1000)
    target = Target(protocol="enip", host=host, port=port, unit=1)
    return EnipAdapter(pool, config), pool, target


async def test_enip_probe_ok_with_identity(enip_server):
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.layer_hint == "application"
        assert r.identity["vendor_id"] == 1
        assert r.identity["product_name"] == "plctap-fixture"
    finally:
        await pool.close_all()


async def test_enip_probe_silent():
    s = FakeEnipServer(mode="silent")
    host, port = await s.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.probe(target)
        assert not r.reachable and r.failure_class == "connected_but_no_reply"
    finally:
        await pool.close_all()
        await s.stop()


async def test_enip_read_dint(enip_server):
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        r = await adapter.read(target, "alpha[0]", 3, datatype="dint")
        assert r.raw_registers == [42, 0, 43, 0, 44, 0]  # 每元素 2 字 (LE 拆)
        assert r.interpreted == [42, 43, 44]
    finally:
        await pool.close_all()


async def test_enip_read_real_float32(enip_server):
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        r = await adapter.read(target, "beta[0]", 2, datatype="float32")
        assert r.interpreted == pytest.approx([0.25, 0.5])
    finally:
        await pool.close_all()


async def test_enip_read_requires_string_address(enip_server):
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        with pytest.raises(ValueError, match="tag name string"):
            await adapter.read(target, 100, 1)
    finally:
        await pool.close_all()


async def test_enip_unknown_tag_cip_status(enip_server):
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        with pytest.raises(ProtocolError, match="PATH_DESTINATION_UNKNOWN"):
            await adapter.read(target, "nope[0]", 1)
    finally:
        await pool.close_all()


async def test_enip_write_then_readback(enip_server):
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        w = await adapter.write(target, "alpha[0]", [70, 80, 90])
        assert w["response_frame"]
        assert enip_server.stored["alpha"] == [70, 80, 90]
    finally:
        await pool.close_all()


async def test_enip_write_audit_on_frame(enip_server):
    """审计回调在发送前拿到完整帧 (红线 2)。"""
    seen: list[str] = []
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        await adapter.write(target, "alpha[0]", [70], on_frame=seen.append)
        assert seen and bytes.fromhex(seen[0])[0:2] == b"\x6f\x00"
    finally:
        await pool.close_all()


async def test_enip_send_raw_register_session(enip_server):
    adapter, pool, target = make_adapter(*enip_server.addr)
    try:
        ex = await adapter.send_raw(target, codec.build_register_session().hex())
        assert ex.received_frame.startswith(b"\x65\x00".hex())
    finally:
        await pool.close_all()
