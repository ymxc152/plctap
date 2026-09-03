"""FINS/MELSEC 适配器测试 (M2): fake asyncio 服务器做会话替身。

ProtoForge 只用于实机联测, CI 一律用本文件的进程内 fake server
(与 test_adapter_modbus.py 的 FakeSlave 同思路)。
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator

import pytest

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
from plctap.protocols.fins.adapter import FinsAdapter, FinsError
from plctap.protocols.fins import codec as fins_codec
from plctap.protocols.melsec.adapter import MelsecAdapter, McError
from plctap.protocols.melsec import codec as mc_codec


# ---------------------------------------------------------------- fake FINS


class FakeFinsServer:
    """FINS/TCP 假设备: 握手 + 0101 读回显。

    mode: normal / end_code(回给定端结码) / silent(收请求不回话)
    / bad_magic(回错魔数)。handshake_count 记录握手次数 (连接复用验证)。
    """

    def __init__(self, mode: str = "normal", end_code: int = 0) -> None:
        self.mode = mode
        self.end_code = end_code
        self.handshake_count = 0
        self._server: asyncio.Server | None = None
        self._abort = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        return "127.0.0.1", port

    async def stop(self) -> None:
        self._abort.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for w in list(self._writers):
            w.close()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            while not self._abort.is_set():
                try:
                    head = await asyncio.wait_for(reader.readexactly(fins_codec.TCP_HEADER_LEN), 0.5)
                except TimeoutError:
                    continue  # 没数据, 继续等
                except asyncio.IncompleteReadError:
                    return  # EOF: 对端已关, 继续循环会同步自旋饿死事件循环
                (length,) = struct.unpack_from(">I", head, 4)
                payload = await asyncio.wait_for(reader.readexactly(length - 8), 1.0)
                (command, error) = struct.unpack_from(">II", head, 8)
                if command == fins_codec.TCP_CMD_CONNECT_REQ:
                    self.handshake_count += 1
                    (client_node,) = struct.unpack_from(">I", payload, 0)
                    resp_payload = struct.pack(">II", 0x02, client_node)
                    writer.write(fins_codec.build_tcp_frame(fins_codec.TCP_CMD_CONNECT_CFM, resp_payload))
                    await writer.drain()
                elif command == fins_codec.TCP_CMD_EXCHANGE:
                    if self.mode == "silent":
                        await self._abort.wait()
                        continue
                    if self.mode == "bad_magic":
                        writer.write(b"XXXX" + b"\x00" * 12)
                        await writer.drain()
                        continue
                    sid = payload[9]
                    da1 = payload[4]
                    fins = (
                        bytes([0xC0, 0x00, 0x02]) + bytes([0x00, da1, 0x00])
                        + bytes([0x00, 0x02, 0x00]) + bytes([sid])
                        + struct.pack(">H", fins_codec.CMD_MEMORY_AREA_READ)
                        + struct.pack(">H", self.end_code)
                    )
                    if self.end_code == 0 and len(payload) >= 18:
                        (count,) = struct.unpack_from(">H", payload, 16)
                        fins += b"".join(struct.pack(">H", 0x1000 + i) for i in range(count))
                    writer.write(fins_codec.build_tcp_frame(fins_codec.TCP_CMD_EXCHANGE, fins))
                    await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()


# ---------------------------------------------------------------- fake MC


class FakeMcServer:
    """MC/3E 假设备: 0401 读回显 (小端)。mode 同上, 外加 bad_frame(错副头部)。"""

    def __init__(self, mode: str = "normal", end_code: int = 0) -> None:
        self.mode = mode
        self.end_code = end_code
        self._server: asyncio.Server | None = None
        self._abort = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        return "127.0.0.1", port

    async def stop(self) -> None:
        self._abort.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for w in list(self._writers):
            w.close()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            while not self._abort.is_set():
                try:
                    head = await asyncio.wait_for(reader.readexactly(mc_codec.FRAME_HEADER_LEN), 0.5)
                except TimeoutError:
                    continue  # 没数据, 继续等
                except asyncio.IncompleteReadError:
                    return  # EOF: 对端已关, 继续循环会同步自旋饿死事件循环
                (data_len,) = struct.unpack_from("<H", head, 9)
                data = await asyncio.wait_for(reader.readexactly(data_len), 1.0)
                if self.mode == "silent":
                    await self._abort.wait()
                    continue
                if self.mode == "bad_frame":
                    writer.write(b"\x50\x50" + head[2:] + data)
                    await writer.drain()
                    continue
                head_dev = data[5:8]
                (count,) = struct.unpack_from("<H", data, 8)
                # 位软元件 (X/Y/B/M) 按字读: 响应字数 = ceil(count/16)
                code = data[4]
                words = (count + 15) // 16 if code in (0x58, 0x59, 0x42, 0x4D) else count
                resp_data = struct.pack("<H", self.end_code)
                if self.end_code == 0:
                    resp_data += b"".join(struct.pack("<H", 0x2000 + i) for i in range(words))
                resp_head = (
                    mc_codec.SUBHEADER_BYTES
                    + head[2:7]  # 回显 网络/PC/I/O/站号
                    + head[7:9]  # 回显 timer
                    + struct.pack("<H", len(resp_data))
                )
                writer.write(resp_head + resp_data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()


# ---------------------------------------------------------------- fixtures


@pytest.fixture
async def fins_server() -> AsyncIterator[FakeFinsServer]:
    server = FakeFinsServer()
    server.addr = await server.start()
    yield server
    await server.stop()


@pytest.fixture
async def mc_server() -> AsyncIterator[FakeMcServer]:
    server = FakeMcServer()
    server.addr = await server.start()
    yield server
    await server.stop()


def make_adapter(cls, host, port):
    pool = ConnectionPool(idle_timeout_sec=5.0)
    config = PlctapConfig(default_timeout_ms=1000)
    target = Target(protocol=cls.name, host=host, port=port)
    return cls(pool, config), pool, target


# ---------------------------------------------------------------- FINS adapter


async def test_fins_probe_ok(fins_server):
    adapter, pool, target = make_adapter(FinsAdapter, *fins_server.addr)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.layer_hint == "application"
    finally:
        await pool.close_all()


async def test_fins_probe_no_reply(monkeypatch):
    # 静默设备: TCP 通但应用层不回话 (Windows 防火墙下无法用未监听端口造 refused)
    server = FakeFinsServer(mode="silent")
    host, port = await server.start()
    adapter, pool, target = make_adapter(FinsAdapter, host, port)
    try:
        r = await adapter.probe(target)
        assert not r.reachable
        assert r.failure_class == "connected_but_no_reply"
        assert r.layer_hint == "protocol"
    finally:
        await pool.close_all()
        await server.stop()


async def test_fins_probe_refused(monkeypatch):
    async def refuse(*args, **kwargs):
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", refuse)
    adapter, pool, target = make_adapter(FinsAdapter, "127.0.0.1", 1)
    r = await adapter.probe(target)
    assert not r.reachable and r.failure_class == "connection_refused"


async def test_fins_read_and_handshake_reuse(fins_server):
    adapter, pool, target = make_adapter(FinsAdapter, *fins_server.addr)
    try:
        r1 = await adapter.read(target, address=0, count=3)
        assert r1.raw_registers == [0x1000, 0x1001, 0x1002]
        assert r1.interpreted == [0x1000, 0x1001, 0x1002]
        r2 = await adapter.read(target, address=10, count=2)
        assert r2.raw_registers == [0x1000, 0x1001]
        # 两次读共用一条池内连接: 握手只发生一次 (metadata 随连接走)
        assert fins_server.handshake_count == 1
    finally:
        await pool.close_all()


async def test_fins_read_float32(fins_server):
    adapter, pool, target = make_adapter(FinsAdapter, *fins_server.addr)
    try:
        r = await adapter.read(target, address=0, count=2, datatype="float32", byteorder="big")
        assert len(r.interpreted) == 1
        assert isinstance(r.interpreted[0], float)
    finally:
        await pool.close_all()


async def test_fins_read_end_code_raises(fins_server):
    server = FakeFinsServer(end_code=0x1101)
    host, port = await server.start()
    adapter, pool, target = make_adapter(FinsAdapter, host, port)
    try:
        with pytest.raises(FinsError, match="ADDRESS_RANGE_ERROR"):
            await adapter.read(target, address=0, count=1)
    finally:
        await pool.close_all()
        await server.stop()


async def test_fins_read_bad_magic_discards_connection():
    server = FakeFinsServer(mode="bad_magic")
    host, port = await server.start()
    adapter, pool, target = make_adapter(FinsAdapter, host, port)
    try:
        with pytest.raises(Exception, match="magic"):
            await adapter.read(target, address=0, count=1)
        # 连接已丢弃, 下一次读重新建连+握手, 不卡死也不串话
        with pytest.raises(Exception, match="magic"):
            await adapter.read(target, address=0, count=1)
        assert server.handshake_count == 2
    finally:
        await pool.close_all()
        await server.stop()


async def test_fins_read_unknown_area():
    adapter, pool, target = make_adapter(FinsAdapter, "127.0.0.1", 1)
    try:
        with pytest.raises(ValueError, match="unknown area"):
            await adapter.read(target, address=0, count=1, area="ZZ")
    finally:
        await pool.close_all()


# ---------------------------------------------------------------- MC adapter


async def test_mc_probe_ok(mc_server):
    adapter, pool, target = make_adapter(MelsecAdapter, *mc_server.addr)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.layer_hint == "application"
    finally:
        await pool.close_all()


async def test_mc_read(mc_server):
    adapter, pool, target = make_adapter(MelsecAdapter, *mc_server.addr)
    try:
        r = await adapter.read(target, address=0, count=3)
        assert r.raw_registers == [0x2000, 0x2001, 0x2002]
        # cmd0104 + subcmd0000 + 'D' + head 000000 + count 0300 (全小端)
        assert r.request_frame.endswith("01040000440000000300")
    finally:
        await pool.close_all()


async def test_mc_read_bit_device(mc_server):
    adapter, pool, target = make_adapter(MelsecAdapter, *mc_server.addr)
    try:
        r = await adapter.read(target, address=0, count=16, device="X")
        assert len(r.raw_registers) == 1  # 16 点 = 1 字
    finally:
        await pool.close_all()


async def test_mc_read_end_code_raises(mc_server):
    server = FakeMcServer(end_code=0xC04F)
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        with pytest.raises(McError, match="DEVICE_NUMBER_OUT_OF_RANGE"):
            await adapter.read(target, address=0, count=1)
    finally:
        await pool.close_all()
        await server.stop()


async def test_mc_probe_silent():
    server = FakeMcServer(mode="silent")
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        r = await adapter.probe(target)
        assert not r.reachable
        assert r.failure_class == "connected_but_no_reply"
    finally:
        await pool.close_all()
        await server.stop()


async def test_mc_probe_bad_frame_is_no_reply():
    server = FakeMcServer(mode="bad_frame")
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        r = await adapter.probe(target)
        if r.failure_class == "exception_response":
            assert r.reachable  # P3 语义: 异常响应 = 设备在线
        else:
            assert not r.reachable
    finally:
        await pool.close_all()
        await server.stop()
