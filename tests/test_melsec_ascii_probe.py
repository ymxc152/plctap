"""MELSEC probe ASCII 回退专项测试 (自包含, 不 import 其他测试文件的替身)。

probe 语义 (src/plctap/protocols/melsec/adapter.py):
  1. 先发 3E binary 读 D0 x2; 正常完成 -> 直接返回, 行为不变。
  2. binary 交互落入 connected_but_no_reply (TCP 通但没完成一次规范应答)
     -> 用 3E ASCII 重发一次; ASCII 成功 (valid 且 end_code==0) -> reachable。
  3. connection_refused / timeout 属传输层故障, 与帧格式无关 -> 不回退。

替身约定: EOF 必须 return (continue 会同步自旋饿死事件循环, 见
test_adapter_fins_melsec.py 的既有注释; 本文件自包含重写同款注释)。
"""

from __future__ import annotations

import asyncio
import struct

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
from plctap.protocols.melsec.adapter import MelsecAdapter


# ---------------------------------------------------------------- fake server


class FakeMcSingleFormatServer:
    """只说一种帧格式的 MC 假从站 (按请求副头部判别来帧格式)。

    mode:
      ascii_only  - 收到 3E ASCII 请求 (首 4 字节 b"5000") 按 ASCII 回 D000
                    响应 (路由回显 + 4 字符数据长 + 结束码 + 数据);
                    对 binary 请求 (首 2 字节 50 00) 不回复。
      binary_only - 收到 3E binary 请求回 D000 二进制响应;
                    对 ASCII 请求不回复。
      silent      - 什么都收, 从不回复。

    request_kinds / request_frames 记录每个收到的请求 (首 4 字节可判别格式:
    ASCII 帧 b"5000" vs binary 帧 50 00 ..), 供测试断言 probe 的尝试序列。
    """

    def __init__(self, mode: str = "ascii_only") -> None:
        self.mode = mode
        self.request_kinds: list[str] = []
        self.request_frames: list[bytes] = []
        self._server: asyncio.Server | None = None
        self._abort = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()

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

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            while not self._abort.is_set():
                try:
                    head2 = await asyncio.wait_for(reader.readexactly(2), 0.5)
                except TimeoutError:
                    continue  # 没数据, 继续等
                except asyncio.IncompleteReadError:
                    return  # EOF: 对端已关, 继续循环会同步自旋饿死事件循环
                try:
                    await self._handle(head2, reader, writer)
                except (TimeoutError, asyncio.IncompleteReadError):
                    return  # 半截帧/对端中途关闭: 丢弃连接, 不带病续读
        except (ConnectionError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()

    async def _handle(self, head2: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if head2 == b"50":
            # 3E ASCII 请求: 22 字符头, 数据长 @14 (4 字符, 含定时器 4 字符)
            head = head2 + await asyncio.wait_for(reader.readexactly(20), 1.0)
            if head[:4] != b"5000":
                return  # 不是 3E ASCII 请求, 静默
            (dlen,) = (int(head[14:18], 16),)
            body = await asyncio.wait_for(reader.readexactly(dlen - 4), 1.0)  # 去掉定时器 4 字符
            kind, frame = "3e_ascii", head + body
        elif head2 == b"\x50\x00":
            # 3E binary 请求: 11B 头, 数据长 @7 (2B LE, 含定时器 2B)
            head = head2 + await asyncio.wait_for(reader.readexactly(9), 1.0)
            (dlen,) = struct.unpack_from("<H", head, 7)
            body = await asyncio.wait_for(reader.readexactly(dlen - 2), 1.0)  # 去掉定时器 2B
            kind, frame = "3e_binary", head + body
        else:
            return  # 未知副头部 (probe 不会发 4E), 静默
        self.request_kinds.append(kind)
        self.request_frames.append(frame)
        if self.mode == "silent":
            return
        if (kind == "3e_ascii") != (self.mode == "ascii_only"):
            return  # 不是本从站配置的格式: 不回复 (probe 应回退到另一格式)
        resp = self._build_read_response(frame, kind)
        writer.write(resp)
        await writer.drain()

    @staticmethod
    def _build_read_response(frame: bytes, kind: str) -> bytes:
        """0401 批量读回显: 结束码 0000 + 每字 0x2000+i。probe 只发读请求。"""
        if kind == "3e_ascii":
            payload = frame[22:]  # 定时器之后
            (count,) = (int(payload[16:20], 16),)
            words_txt = "".join(f"{(0x2000 + i) & 0xFFFF:04X}" for i in range(count))
            data = ("0000" + words_txt).encode()
            # D000 + 路由回显(10 字符) + 4 字符数据长 + 结束码 + 数据
            return b"D000" + frame[4:14] + f"{len(data):04X}".encode() + data
        code = frame[11 + 7]
        (count,) = struct.unpack_from("<H", frame, 11 + 8)
        words = (count + 15) // 16 if code in (0x9C, 0x9D, 0xA0, 0x90) else count
        data = struct.pack("<H", 0) + b"".join(struct.pack("<H", 0x2000 + i) for i in range(words))
        # D0 00 + 路由回显(5B) + 数据长(2B LE) + 结束码 + 数据
        return b"\xd0\x00" + frame[2:7] + struct.pack("<H", len(data)) + data


# ---------------------------------------------------------------- helpers


def make_adapter(host: str, port: int):
    pool = ConnectionPool(idle_timeout_sec=5.0)
    config = PlctapConfig(default_timeout_ms=500)
    target = Target(protocol=MelsecAdapter.name, host=host, port=port)
    return MelsecAdapter(pool, config), pool, target


# ---------------------------------------------------------------- tests


async def test_probe_ascii_only_slave_falls_back_to_ascii():
    """纯 ASCII 从站静默丢弃 binary 请求 -> probe 回退 ASCII 后可达。"""
    server = FakeMcSingleFormatServer(mode="ascii_only")
    host, port = await server.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.probe(target)
        assert r.reachable, r.failure_class
        assert r.failure_class is None
        assert r.layer_hint == "application"
        # 尝试序列: 先 binary (被静默), 再 ASCII 回退成功
        assert server.request_kinds == ["3e_binary", "3e_ascii"]
        assert server.request_frames[0][:2] == b"\x50\x00"  # binary 请求帧
        assert server.request_frames[1][:4] == b"5000"  # ASCII 请求帧首 4 字节
    finally:
        await pool.close_all()
        await server.stop()


async def test_probe_binary_only_slave_single_binary_attempt():
    """binary 从站第一次尝试即成功: probe 行为不变, 不发 ASCII 请求。"""
    server = FakeMcSingleFormatServer(mode="binary_only")
    host, port = await server.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.probe(target)
        assert r.reachable, r.failure_class
        assert r.failure_class is None
        assert r.layer_hint == "application"
        # 只进行过一次 binary 交互 (按请求帧首字节判别), 无 ASCII 回退
        assert server.request_kinds == ["3e_binary"]
        assert len(server.request_frames) == 1
        assert server.request_frames[0][:2] == b"\x50\x00"
        assert server.request_frames[0][:4] != b"5000"
    finally:
        await pool.close_all()
        await server.stop()


async def test_probe_all_silent_still_reports_no_reply():
    """binary/ASCII 都不回话的设备: 回退发生后仍如实报 connected_but_no_reply。"""
    server = FakeMcSingleFormatServer(mode="silent")
    host, port = await server.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.probe(target)
        assert not r.reachable
        assert r.failure_class == "connected_but_no_reply"
        assert r.layer_hint == "protocol"
        # 两种格式都试过, 但不虚报在线
        assert server.request_kinds == ["3e_binary", "3e_ascii"]
    finally:
        await pool.close_all()
        await server.stop()


async def test_probe_connection_refused_skips_ascii_fallback(monkeypatch):
    """connection_refused 是传输层故障, 与帧格式无关: 不做 ASCII 回退。"""
    calls = {"n": 0}

    async def refuse(*args, **kwargs):
        calls["n"] += 1
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", refuse)
    adapter, pool, target = make_adapter("127.0.0.1", 1)
    try:
        r = await adapter.probe(target)
        assert not r.reachable
        assert r.failure_class == "connection_refused"
        assert calls["n"] == 1  # 只连接一次, 无第二次 (ASCII) 尝试
    finally:
        await pool.close_all()
