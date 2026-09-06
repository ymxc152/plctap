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
                elif command in fins_codec.FINS_EXCHANGE_COMMANDS:
                    if self.mode == "silent":
                        await self._abort.wait()
                        continue
                    if self.mode == "bad_magic":
                        writer.write(b"XXXX" + b"\x00" * 12)
                        await writer.drain()
                        continue
                    sid = payload[9]
                    da1 = payload[4]
                    (fins_cmd,) = struct.unpack_from(">H", payload, 10)
                    resp_cmd = (
                        fins_codec.CMD_MEMORY_AREA_WRITE
                        if fins_cmd == fins_codec.CMD_MEMORY_AREA_WRITE
                        else fins_codec.CMD_MEMORY_AREA_READ
                    )
                    fins = (
                        bytes([0xC0, 0x00, 0x02]) + bytes([0x00, da1, 0x00])
                        + bytes([0x00, 0x02, 0x00]) + bytes([sid])
                        + struct.pack(">H", resp_cmd)
                        + struct.pack(">H", self.end_code)
                    )
                    if resp_cmd == fins_codec.CMD_MEMORY_AREA_READ and self.end_code == 0 and len(payload) >= 18:
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
                (data_len,) = struct.unpack_from("<H", head, 7)
                data = await asyncio.wait_for(reader.readexactly(data_len - 2), 1.0)  # 去掉定时器 2B
                if self.mode == "silent":
                    await self._abort.wait()
                    continue
                if self.mode == "bad_frame":
                    writer.write(b"\x50\x50" + head[2:] + data)
                    await writer.drain()
                    continue
                (count,) = struct.unpack_from("<H", data, 8)
                # 位软元件 (X/Y/B/M) 按字读: 响应字数 = ceil(count/16)
                code = data[7]
                words = (count + 15) // 16 if code in (0x9C, 0x9D, 0xA0, 0x90) else count
                resp_data = struct.pack("<H", self.end_code)
                if self.end_code == 0:
                    resp_data += b"".join(struct.pack("<H", 0x2000 + i) for i in range(words))
                resp_head = (
                    mc_codec.RESPONSE_SUBHEADER_BYTES
                    + head[2:7]  # 回显 网络/PC/I/O/站号
                    + struct.pack("<H", len(resp_data))  # 响应数据长 = 结束码+数据
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
        assert r.request_frame.endswith("01040000000000a80300")
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


# ---------------------------------------------------------------- MC 多帧格式 (回归: frame_format 必须贯穿到收帧)


class FakeMcServerAuto:
    """按请求副头部自动判别格式并以同一格式回帧的假设备。

    回归背景: locked_exchange 未把 frame_format 传给 _recv_frame 时,
    3E ASCII / 4E 帧的响应会被按 3E binary 切帧解析而报
    "bad ... response subheader 0x4430"。
    """

    def __init__(self, mode: str = "normal") -> None:
        # mode: normal / ascii_only_error (binary 请求回 ASCII 数据代码错误帧)
        #       / ascii_only_silent (binary 请求静默丢弃)
        self.mode = mode
        self._server: asyncio.Server | None = None
        self._abort = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()
        self.formats_seen: list[str] = []

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
                    continue
                except asyncio.IncompleteReadError:
                    return
                is_ascii = head2 in (b"50", b"54")
                is_4e = head2 in (b"\x54\x00", b"54")
                req_head_len = 30 if (is_ascii and is_4e) else 22 if is_ascii else 15 if is_4e else 11
                dlen_off = 22 if (is_ascii and is_4e) else 14 if is_ascii else 11 if is_4e else 7
                dlen_raw = await asyncio.wait_for(reader.readexactly(req_head_len - 2), 1.0)
                head = head2 + dlen_raw
                if is_ascii:
                    dlen = int(head[dlen_off:dlen_off + 4], 16)
                else:
                    (dlen,) = struct.unpack_from("<H", head, dlen_off)
                body = await asyncio.wait_for(reader.readexactly(dlen - (4 if is_ascii else 2)), 1.0)  # dlen 含定时器
                frame = head + body
                fmt = ("4e" if is_4e else "3e") + ("_ascii" if is_ascii else "_binary")
                self.formats_seen.append(fmt)
                if self.mode.startswith("ascii_only") and not is_ascii:
                    if self.mode == "ascii_only_silent":
                        continue  # 静默丢弃 binary 请求
                    # ASCII 设备收到 binary 请求: 回 ASCII 数据代码错误帧 (C059)
                    resp = b"D000" + frame[4:14] + b"0004" + b"C059"
                    writer.write(resp)
                    await writer.drain()
                    continue
                if is_ascii:
                    payload = frame[30:] if is_4e else frame[22:]  # 定时器之后
                    cmd = int(payload[0:4], 16)
                    resp_sub = b"D400" if is_4e else b"D000"
                    echo = frame[4:22] if is_4e else frame[4:14]
                    if cmd == 0x1401:  # 批量写: 回 endcode-only
                        data = f"{self._END:04X}".encode()
                        resp = resp_sub + echo + f"{len(data):04X}".encode() + data
                        writer.write(resp)
                        await writer.drain()
                        continue
                    (count,) = (int(payload[16:20], 16),)
                    end_txt = f"{self._END:04X}"
                    words_txt = "".join(f"{(0x2000 + i) & 0xFFFF:04X}" for i in range(count))
                    data = (end_txt + words_txt).encode()
                    resp = resp_sub + echo + f"{len(data):04X}".encode() + data
                else:
                    payload = frame[15:] if is_4e else frame[11:]
                    (cmd,) = struct.unpack_from("<H", payload, 0)
                    end_bytes = struct.pack("<H", self._END)
                    resp_sub = b"\xd4\x00" if is_4e else b"\xd0\x00"
                    echo = frame[2:11] if is_4e else frame[2:7]
                    if cmd == 0x1401:  # 批量写: 回 endcode-only
                        resp = resp_sub + echo + struct.pack("<H", len(end_bytes)) + end_bytes
                        writer.write(resp)
                        await writer.drain()
                        continue
                    (count,) = struct.unpack_from("<H", payload, 8)
                    words_bytes = b"".join(struct.pack("<H", (0x2000 + i) & 0xFFFF) for i in range(count))
                    data = end_bytes + words_bytes
                    resp = resp_sub + echo + struct.pack("<H", len(data)) + data
                writer.write(resp)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()

    _END = 0


@pytest.mark.parametrize("fmt", list(mc_codec.FRAME_FORMATS))
async def test_mc_read_all_frame_formats(fmt):
    server = FakeMcServerAuto()
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        r = await adapter.read(target, address=100, count=4, device="D", frame_format=fmt)
        assert r.raw_registers == [0x2000, 0x2001, 0x2002, 0x2003]
        assert server.formats_seen == [fmt]
    finally:
        await pool.close_all()
        await server.stop()


async def test_mc_send_raw_auto_format():
    """send_raw 收帧按响应副头部自动判别 (无法预知对端格式)。"""
    server = FakeMcServerAuto()
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        req = mc_codec.build_read_request("D", 0, 2, frame_format="4e_ascii")
        ex = await adapter.send_raw(target, req.hex())
        assert ex.received_frame.startswith(b"D400".hex()) or ex.received_frame.startswith("d400")
    finally:
        await pool.close_all()
        await server.stop()


async def test_mc_probe_ascii_device_error_to_binary():
    """ASCII 模式设备对 binary 请求回 ASCII 错误帧 -> probe 第二次尝试 ASCII 请求成功。"""
    server = FakeMcServerAuto(mode="ascii_only_error")
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.failure_class is None
        assert server.formats_seen == ["3e_binary", "3e_ascii"]
    finally:
        await pool.close_all()
        await server.stop()


async def test_mc_probe_ascii_device_silent_to_binary():
    """ASCII 模式设备静默丢弃 binary 请求 -> probe 回退 ASCII 请求成功。"""
    server = FakeMcServerAuto(mode="ascii_only_silent")
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.failure_class is None
        assert server.formats_seen == ["3e_binary", "3e_ascii"]
    finally:
        await pool.close_all()
        await server.stop()


async def test_mc_probe_binary_device_single_attempt():
    """binary 设备第一次尝试即正常完成, 不发第二次请求。"""
    server = FakeMcServerAuto()
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.failure_class is None
        assert server.formats_seen == ["3e_binary"]
    finally:
        await pool.close_all()
        await server.stop()


# ---------------------------------------------------------------- write (1401 / 0102)


@pytest.mark.parametrize("fmt", list(mc_codec.FRAME_FORMATS))
async def test_mc_write_all_frame_formats(fmt):
    """1401 批量写: 四种帧格式请求-响应闭环 + 审计留痕。"""
    server = FakeMcServerAuto()
    host, port = await server.start()
    adapter, pool, target = make_adapter(MelsecAdapter, host, port)
    audit: list[str] = []
    try:
        r = await adapter.write(
            target, 100, [11, 22, 0xFFFF], device="D", frame_format=fmt,
            on_frame=audit.append,
        )
        assert r["request_frame"] and r["response_frame"]
        assert len(r["request_frame"]) > 0 and r["elapsed_ms"] >= 0
        assert len(audit) == 1 and audit[0] == r["request_frame"]
        assert server.formats_seen == [fmt]
    finally:
        await pool.close_all()
        await server.stop()


async def test_mc_write_codec_layouts():
    """1401 请求帧布局: binary 小端 + ascii hex 文本, 与 0401 同构。"""
    req = mc_codec.build_write_request("D", 100, [0x04D2, 0x162E])
    # binary: 副头部 5000 + 路由 + 数据长 + 定时器 + cmd 1401 + subcmd 0000
    assert req[0:2] == b"\x50\x00"
    body = req[11:]
    assert body[0:2] == b"\x01\x14"  # cmd 0x1401 LE
    assert body[2:4] == b"\x00\x00"  # subcmd
    assert body[4:7] == (100).to_bytes(3, "little")  # head
    assert body[7] == 0xA8  # D
    assert body[8:10] == struct.pack("<H", 2)  # count
    assert body[10:14] == struct.pack("<HH", 0x04D2, 0x162E)  # values 小端
    # 解析器应能读回
    parsed = mc_codec.parse_request_fmt(req)
    assert parsed.valid
    fields = {f.name: f.value for f in parsed.fields}
    assert fields["command"] == 0x1401 and fields["head_device"] == 100


async def test_mc_write_rejects_bit_device_semantics_and_ranges():
    with pytest.raises(ValueError, match="values must not be empty"):
        mc_codec.build_write_request("D", 100, [])
    with pytest.raises(ValueError, match="16-bit word range"):
        mc_codec.build_write_request("D", 100, [70000])
    with pytest.raises(ValueError, match="unknown device"):
        mc_codec.build_write_request("Z", 100, [1])


async def test_fins_write_layout_and_endcode():
    """0102 请求布局 + endcode-only 响应解析。"""
    req = fins_codec.build_memory_area_write(7, 1, fins_codec.AREA_CODES["DM"], 200, [0x0309, 0x0378])
    assert req[:4] == b"FINS"
    assert req[8:12] == b"\x00\x00\x00\x02"  # TCP 数据命令 0x02
    payload = req[16:]
    assert payload[0] == 0x80  # ICF
    assert struct.unpack_from(">H", payload, 10)[0] == fins_codec.CMD_MEMORY_AREA_WRITE
    assert payload[12] == fins_codec.AREA_CODES["DM"]
    assert int.from_bytes(payload[13:15], "big") == 200
    assert struct.unpack_from(">H", payload, 16)[0] == 2
    assert struct.unpack_from(">HH", payload, 18) == (0x0309, 0x0378)
    # 响应: endcode 0, 无数据; 响应路由 = 请求路由对调 (SA1 应为请求的 DA1=0)
    resp = fins_codec.build_tcp_frame(
        fins_codec.TCP_CMD_EXCHANGE,
        bytes([0xC0, 0x00, 0x02]) + bytes([0x00, 1, 0x00]) + bytes([0x00, 0, 0x00])
        + bytes([7]) + struct.pack(">H", fins_codec.CMD_MEMORY_AREA_WRITE)
        + struct.pack(">H", 0),
    )
    parsed = fins_codec.parse_response(resp, request=req)
    assert parsed.valid, parsed.errors
    end_field = next(f for f in parsed.fields if f.name == "end_code")
    assert end_field.value == 0


async def test_fins_write_adapter_roundtrip():
    """FINS 适配器写: 0102 请求 -> endcode 响应 -> 审计留痕。"""
    server = FakeFinsServer()
    host, port = await server.start()
    adapter, pool, target = make_adapter(FinsAdapter, host, port)
    audit: list[str] = []
    try:
        r = await adapter.write(target, 200, [777, 888], area="DM", on_frame=audit.append)
        assert r["request_frame"] and r["elapsed_ms"] >= 0
        assert len(audit) == 1 and audit[0] == r["request_frame"]
        # 请求帧里 cmd 应为 0102
        req = bytes.fromhex(r["request_frame"])
        assert struct.unpack_from(">H", req, 26)[0] == fins_codec.CMD_MEMORY_AREA_WRITE
    finally:
        await pool.close_all()
        await server.stop()


async def test_fins_write_end_code_raises():
    server = FakeFinsServer(end_code=0x1101)
    host, port = await server.start()
    adapter, pool, target = make_adapter(FinsAdapter, host, port)
    try:
        with pytest.raises(FinsError, match="ADDRESS_RANGE_ERROR"):
            await adapter.write(target, 200, [1], area="DM")
    finally:
        await pool.close_all()
        await server.stop()


async def test_fins_write_rejects_coil_point_type():
    adapter, pool, target = make_adapter(FinsAdapter, "127.0.0.1", 1)
    try:
        with pytest.raises(ValueError, match="point_type"):
            await adapter.write(target, 0, [1], point_type="coil")
    finally:
        await pool.close_all()
