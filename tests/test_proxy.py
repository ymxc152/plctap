"""透明代理测试 (v0.4): 真实 socket 三方拓扑, 透传 + 分帧录制 + 盲转兜底。

拓扑: client → ProxyRegistry → fake upstream (进程内, 端口 0 系统分配)。
覆盖: modbus/melsec 读写闭环与帧录制、协议不匹配时盲转不阻断、生命周期。
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from plctap import streams
from plctap.protocols.melsec import codec as mc_codec
from plctap.protocols.modbus import codec as modbus_codec
from plctap.proxy import ProxyRegistry


class _FakeBase:
    """共用生命周期: stop 时关 server 并断开全部活跃连接, 让 handler 立即退出。

    (handler 若只靠读超时续命, stop 的 wait_closed 会永远等不到它退出。)
    """

    def __init__(self) -> None:
        self._server: asyncio.AbstractServer | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        for w in list(self._writers):
            w.close()
        await self._server.wait_closed()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            await self._serve_client(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, OSError, TimeoutError):
            pass
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()


class FakeModbusSlave(_FakeBase):
    """最小 modbus 从站: fc03 回 byte_count=2*qty 的零数据。"""

    async def _serve_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            try:
                head = await asyncio.wait_for(reader.readexactly(6), 1.0)
            except TimeoutError:
                continue
            except asyncio.IncompleteReadError:
                return
            (length,) = struct.unpack_from(">H", head, 4)
            # MBAP length 字段 = 其后所有字节 (unit + PDU)
            pdu = await asyncio.wait_for(reader.readexactly(length), 1.0)
            unit, fc = pdu[0], pdu[1]
            if fc in (3, 4):
                (qty,) = struct.unpack_from(">H", pdu, 4)
                body = bytes([fc, qty * 2]) + b"\x00" * (qty * 2)
                writer.write(
                    head[0:2] + b"\x00\x00" + struct.pack(">H", len(body) + 1) + bytes([unit]) + body
                )
                await writer.drain()
            else:
                return


class FakeMelsecSlave(_FakeBase):
    """最小 3E binary 从站: 0401 回端结码 0 + 零数据 (响应无定时器)。"""

    async def _serve_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        buf = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), 1.0)
            if not chunk:
                return
            buf += chunk
            while True:
                n = streams.try_frame_len("melsec", buf)
                if n is None or n == 0:
                    break
                frame, buf = buf[:n], buf[n:]
                body = frame[11:]
                (count,) = struct.unpack_from("<H", body, 8)
                data = struct.pack("<H", 0) + b"\x00" * (count * 2)
                writer.write(b"\xd0\x00" + frame[2:7] + struct.pack("<H", len(data)) + data)
                await writer.drain()


class EchoServer(_FakeBase):
    """协议无关回显: 用于验证盲转兜底 (录制失败不阻断通信)。"""

    async def _serve_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), 1.0)
            if not chunk:
                return
            writer.write(chunk)
            await writer.drain()


async def _roundtrip(port: int, data: bytes, protocol: str, timeout: float = 2.0) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
    try:
        writer.write(data)
        await writer.drain()
        buf = bytearray()
        while True:
            n = streams.try_frame_len(protocol, buf)
            if n is not None and n > 0:
                return bytes(buf[:n])
            chunk = await asyncio.wait_for(reader.read(4096), timeout)
            if not chunk:
                return b""
            buf.extend(chunk)
    finally:
        writer.close()


async def _recv_raw(port: int, data: bytes, expect_len: int, timeout: float = 2.0) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
    try:
        writer.write(data)
        await writer.drain()
        buf = b""
        while len(buf) < expect_len:
            chunk = await asyncio.wait_for(reader.read(4096), timeout)
            if not chunk:
                break
            buf += chunk
        return buf
    finally:
        writer.close()


@pytest.fixture
async def registry():
    reg = ProxyRegistry()
    yield reg
    for port in list(reg.active_ports()):
        try:
            await reg.stop(port)
        except Exception:
            pass


async def test_modbus_proxy_roundtrip_and_frames(registry):
    slave = FakeModbusSlave()
    target_port = await slave.start()
    try:
        info = await registry.start("modbus", "127.0.0.1", 0, "127.0.0.1", target_port)
        proxy_port = info["listen_port"]
        req = modbus_codec.build_read_request(7, 1, modbus_codec.READ_HOLDING_REGISTERS, 5, 3)
        resp = await _roundtrip(proxy_port, req, "modbus")
        # 响应经代理原样可达且自洽 (tid 回显 + byte_count = 2*qty)
        assert resp[0:2] == req[0:2] and resp[7] == 3 and resp[8] == 6
        frames = registry.frames(proxy_port)
        assert [f["direction"] for f in frames] == ["c2s", "s2c"]
        assert frames[0]["frame_hex"] == req.hex()
        assert frames[1]["frame_hex"] == resp.hex()
    finally:
        await slave.stop()


async def test_melsec_proxy_frames(registry):
    slave = FakeMelsecSlave()
    target_port = await slave.start()
    try:
        info = await registry.start("melsec", "127.0.0.1", 0, "127.0.0.1", target_port)
        proxy_port = info["listen_port"]
        req = mc_codec.build_read_request("D", 100, 4)
        resp = await _roundtrip(proxy_port, req, "melsec")
        assert resp[0:2] == b"\xd0\x00" and resp[9:11] == b"\x00\x00"
        frames = registry.frames(proxy_port)
        assert [f["direction"] for f in frames] == ["c2s", "s2c"]
        assert frames[0]["frame_hex"] == req.hex()
        assert frames[1]["frame_hex"] == resp.hex()
    finally:
        await slave.stop()


async def test_blind_relay_when_protocol_mismatch(registry, monkeypatch):
    import plctap.proxy as proxy_mod

    monkeypatch.setattr(proxy_mod, "_BLIND_FLUSH_BYTES", 16)
    echo = EchoServer()
    target_port = await echo.start()
    try:
        info = await registry.start("modbus", "127.0.0.1", 0, "127.0.0.1", target_port)
        proxy_port = info["listen_port"]
        # 非 modbus 语义的垃圾流量: 长度字段畸形 → 分帧判 0 → 冲缓冲盲转
        garbage = b"\xaa" * 40
        got = await _recv_raw(proxy_port, garbage, len(garbage))
        assert got == garbage
        assert registry.frames(proxy_port) == []
    finally:
        await echo.stop()


async def test_proxy_stop_stats(registry):
    slave = FakeModbusSlave()
    target_port = await slave.start()
    try:
        info = await registry.start("modbus", "127.0.0.1", 0, "127.0.0.1", target_port)
        proxy_port = info["listen_port"]
        req = modbus_codec.build_read_request(1, 1, modbus_codec.READ_HOLDING_REGISTERS, 0, 1)
        await _roundtrip(proxy_port, req, "modbus")
        stats = await registry.stop(proxy_port)
        assert stats["status"] == "stopped" and stats["c2s"] == 1 and stats["s2c"] == 1
        with pytest.raises((ConnectionRefusedError, OSError, TimeoutError)):
            await _roundtrip(proxy_port, req, "modbus")
    finally:
        await slave.stop()


async def test_proxy_target_down(registry):
    # 上游不可达 (本机关闭端口表现为 SYN 丢弃 → 连接超时): 客户端 TCP 能
    # 建立但拿不到任何字节, 连接被代理关闭
    info = await registry.start("modbus", "127.0.0.1", 0, "127.0.0.1", 1, idle_timeout_sec=2)
    reader, writer = await asyncio.open_connection("127.0.0.1", info["listen_port"])
    try:
        writer.write(b"\x00" * 12)
        await writer.drain()
        try:
            chunk = await asyncio.wait_for(reader.read(4096), 6.0)
            assert chunk == b""
        except TimeoutError:
            pytest.fail("proxy kept the client hanging after upstream failure")
    finally:
        writer.close()


async def test_proxy_unsupported_protocol(registry):
    with pytest.raises(ValueError, match="S7 TPKT"):
        await registry.start("s7", "127.0.0.1", 0, "127.0.0.1", 1)
