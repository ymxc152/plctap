"""钓鱼模式监听测试 (M3: listener.py record_only / respond_normal 两档)。

用真 socket 连 listener, 验证收帧、回包、EOF 不挂起、生命周期管理。
端口用 0 让系统分配, 避免测试并发冲突。
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from plctap import streams
from plctap.listener import ListenerRegistry, _fins_tcp_command
from plctap.protocols.fins import codec as fins_codec
from plctap.protocols.melsec import codec as mc_codec
from plctap.protocols.modbus import codec as modbus_codec


@pytest.fixture
async def registry():
    reg = ListenerRegistry()
    yield reg
    for port in list(reg.active_ports()):
        try:
            await reg.stop(port)
        except Exception:
            pass


async def _start(reg, protocol, **kw):
    info = await reg.start(protocol, "127.0.0.1", 0, kw.pop("mode", "record_only"), **kw)
    return info["port"]


async def _recv_frame(reader: asyncio.StreamReader, protocol: str, timeout: float = 2.0) -> bytes:
    """用与 listener 相同的分帧逻辑收一整帧 (测试端复用 streams)。"""
    buf = bytearray()
    while True:
        n = streams.try_frame_len(protocol, buf)
        if n is not None and n > 0:
            return bytes(buf[:n])
        chunk = await asyncio.wait_for(reader.read(4096), timeout)
        if not chunk:
            return b""
        buf.extend(chunk)


async def _send_only(port: int, data: bytes, timeout: float = 2.0) -> None:
    """只发送不等待响应 (record_only 场景: listener 本来就不回包)。"""
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
    try:
        writer.write(data)
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


async def _roundtrip(port: int, protocol: str, data: bytes, timeout: float = 2.0) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
    try:
        writer.write(data)
        await writer.drain()
        return await _recv_frame(reader, protocol, timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


async def _wait_frames(reg: ListenerRegistry, port: int, n: int, timeout: float = 3.0) -> list[dict]:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        frames = reg.frames(port)
        if len(frames) >= n:
            return frames
        await asyncio.sleep(0.01)
    return reg.frames(port)


# ---------------------------------------------------------------- record_only


async def test_record_only_captures_modbus(registry):
    port = await _start(registry, "modbus", mode="record_only")
    req = modbus_codec.build_read_request(1, 1, 3, 0, 2)
    await _send_only(port, req)
    frames = await _wait_frames(registry, port, 1)
    assert frames[0]["direction"] == "recv"
    assert frames[0]["frame_hex"] == req.hex()


async def test_record_only_no_reply(registry):
    port = await _start(registry, "modbus", mode="record_only")
    req = modbus_codec.build_read_request(1, 1, 3, 0, 2)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(req)
        await writer.drain()
        with pytest.raises((asyncio.TimeoutError, TimeoutError)):
            await asyncio.wait_for(_recv_frame(reader, "modbus", 0.3), 0.4)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


async def test_eof_partial_frame_then_reconnect(registry):
    """半帧后 EOF: handler 必须正常退出 (return), 下一连接仍可用。

    若 EOF 处理成 continue 会形成无挂起自旋饿死事件循环, 此测试会超时。
    """
    port = await _start(registry, "modbus", mode="record_only")
    req = modbus_codec.build_read_request(1, 1, 3, 0, 2)
    # 第一次连接: 只发半帧就断开
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(req[:6])
    await writer.drain()
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ConnectionError):
        pass
    # 第二次连接: 完整帧应正常被记录
    await _send_only(port, req)
    frames = await _wait_frames(registry, port, 1, timeout=3.0)
    assert frames[-1]["frame_hex"] == req.hex()


async def test_double_start_same_port_rejected(registry):
    info = await reg_start(registry, "modbus")
    port = info["port"]
    with pytest.raises(ValueError, match="already running"):
        await registry.start("modbus", "127.0.0.1", port, "record_only")


async def reg_start(reg, protocol):
    return await reg.start(protocol, "127.0.0.1", 0, "record_only")


async def test_stop_returns_stats(registry):
    port = await _start(registry, "modbus", mode="record_only")
    req = modbus_codec.build_read_request(1, 1, 3, 0, 2)
    await _send_only(port, req)
    await _wait_frames(registry, port, 1)
    summary = await registry.stop(port)
    assert summary["recorded"] == 1
    assert summary["status"] == "stopped"
    assert port not in registry.active_ports()


# ---------------------------------------------------------------- respond_normal


async def test_modbus_respond_normal(registry):
    port = await _start(registry, "modbus", mode="respond_normal")
    req = modbus_codec.build_read_request(7, 1, 3, 0, 3)
    resp = await _roundtrip(port, "modbus", req)
    parsed = modbus_codec.parse_response(resp, request=req)
    assert parsed.valid, parsed.errors
    values = next(f.value for f in parsed.fields if f.name == "register_values")
    assert values == [0, 0, 0]  # 最小正常响应: 数据恒 0


async def test_modbus_respond_normal_fc05_echo(registry):
    port = await _start(registry, "modbus", mode="respond_normal")
    req = modbus_codec.build_write_single(3, 1, 6, 100, 42)
    resp = await _roundtrip(port, "modbus", req)
    assert resp == req  # 写单点响应 = 请求回显


async def test_fins_respond_normal_handshake_and_read(registry):
    port = await _start(registry, "fins", mode="respond_normal")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(fins_codec.build_handshake_request(1))
        await writer.drain()
        hs = await _recv_frame(reader, "fins")
        info = fins_codec.parse_handshake_response(hs)
        assert 1 <= info["server_node"] <= 239
        # 后续请求 DA1 定向到握手确认的 server_node (M2 适配器同款逻辑)
        req = fins_codec.build_read_request(
            5, 1, fins_codec.AREA_CODES["DM"], 0, 2, dest_node=info["server_node"]
        )
        writer.write(req)
        await writer.drain()
        resp = await _recv_frame(reader, "fins")
        parsed = fins_codec.parse_response(resp, request=req)
        assert parsed.valid, parsed.errors
        values = next(f.value for f in parsed.fields if f.name == "word_values")
        assert values == [0, 0]
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


async def test_melsec_respond_normal(registry):
    port = await _start(registry, "melsec", mode="respond_normal")
    req = mc_codec.build_read_request("D", 10, 3)
    resp = await _roundtrip(port, "melsec", req)
    parsed = mc_codec.parse_response(resp, request=req)
    assert parsed.valid, parsed.errors
    values = next(f.value for f in parsed.fields if f.name == "word_values")
    assert values == [0, 0, 0]


async def test_respond_normal_records_both_directions(registry):
    port = await _start(registry, "modbus", mode="respond_normal")
    req = modbus_codec.build_read_request(1, 1, 3, 0, 1)
    await _roundtrip(port, "modbus", req)
    frames = await _wait_frames(registry, port, 2)
    dirs = [f["direction"] for f in frames]
    assert dirs == ["recv", "send"]
    assert frames[0]["frame_hex"] == req.hex()


@pytest.mark.parametrize("fmt", ["3e_binary", "3e_ascii", "4e_binary", "4e_ascii"])
def test_melsec_respond_normal_all_formats(fmt):
    """回归: respond_normal 对全部 4 种 MELSEC 帧格式回规范响应帧。"""
    from plctap.listener import build_normal_response
    from plctap.protocols.melsec import codec as mc

    req = mc.build_read_request("D", 100, 5, frame_format=fmt)
    resp = build_normal_response("melsec", req)
    assert resp is not None
    parsed = mc.parse_response_fmt(resp, request=req, frame_format=fmt)
    assert parsed.valid, parsed.errors
    end_field = next(f for f in parsed.fields if f.name == "end_code")
    assert end_field.value == 0
    values = next(f for f in parsed.fields if f.name == "word_values")
    assert values.value == [0] * 5


# ---------------------------------------------------------------- inject_errors (v0.4)


async def _read_raw(port: int, data: bytes, expect_len: int, timeout: float = 2.0) -> bytes:
    """注入帧专用: 原始读固定字节数 (坏帧的长度字段与实际不符, 合规分帧器会卡)。"""
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


async def test_inject_modbus_exception_then_garbage_rotation(registry):
    port = await _start(registry, "modbus", mode="inject_errors", faults=["exception", "garbage"])
    req = modbus_codec.build_read_request(7, 1, 3, 0, 2)
    resp1 = await _roundtrip(port, "modbus", req)
    # 第 1 发: 异常响应 (fc|0x80 + ILLEGAL_DATA_ADDRESS, tid/unit 回显)
    assert resp1[0:2] == req[0:2] and resp1[6] == req[6]
    assert resp1[7] == req[7] | 0x80 and resp1[8] == 0x02
    # 第 2 发: 轮转到 garbage (8 字节全零, 任何解析器都该判非法)
    resp2 = await _read_raw(port, req, 8)
    assert resp2 == b"\x00" * 8


async def test_inject_modbus_bad_length(registry):
    port = await _start(registry, "modbus", mode="inject_errors", faults=["bad_length"])
    req = modbus_codec.build_read_request(1, 1, 3, 0, 2)
    resp = await _read_raw(port, req, 12)
    (length,) = struct.unpack_from(">H", resp, 4)
    assert length == len(resp) - 6 + 1  # 长度字段被 +1, 与实际字节数自相矛盾


async def test_inject_melsec_end_code(registry):
    port = await _start(registry, "melsec", mode="inject_errors", faults=["end_code"])
    req = mc_codec.build_read_request("D", 0, 2)
    resp = await _roundtrip(port, "melsec", req)
    assert struct.unpack_from("<H", resp, 9)[0] == 0xC04F  # DEVICE_NUMBER_OUT_OF_RANGE


async def test_inject_fins_end_code_after_handshake(registry):
    port = await _start(registry, "fins", mode="inject_errors", faults=["end_code"])
    # 握手确认不参与故障轮转 (设备需完成握手才继续吐帧)
    hs = fins_codec.build_handshake_request(11)
    resp_hs = await _roundtrip(port, "fins", hs)
    assert _fins_tcp_command(resp_hs) == fins_codec.TCP_CMD_CONNECT_CFM
    req = fins_codec.build_read_request(1, 11, fins_codec.AREA_CODES["DM"], 0, 2)
    resp = await _roundtrip(port, "fins", req)
    assert struct.unpack_from(">H", resp, 28)[0] == 0x1101  # ADDRESS_RANGE_ERROR


def test_frames_limit_edge_cases(registry):
    """frames 切片语义: 取最新 N 条; limit<=0 显式返回空 (切片 [-0:] 即全量的
    陷阱, 不得把整个环形缓冲泼给调用方); limit 超过缓冲时截到缓冲大小。"""
    from types import SimpleNamespace

    registry._listeners[61000] = SimpleNamespace(frames=[{"i": i} for i in range(5)])
    try:
        assert registry.frames(61000, limit=0) == []
        assert registry.frames(61000, limit=-3) == []
        assert len(registry.frames(61000, limit=500)) == 5  # 超限截到缓冲大小
        assert [f["i"] for f in registry.frames(61000, limit=2)] == [3, 4]  # 最新优先
    finally:
        registry._listeners.pop(61000, None)


async def test_inject_fault_validation(registry):
    reg = registry
    with pytest.raises(ValueError, match="requires faults"):
        await reg.start("modbus", "127.0.0.1", 0, "inject_errors")
    with pytest.raises(ValueError, match="unknown faults"):
        await reg.start("modbus", "127.0.0.1", 0, "inject_errors", faults=["end_code"])
    with pytest.raises(ValueError, match="only valid with"):
        await reg.start("modbus", "127.0.0.1", 0, "record_only", faults=["garbage"])
