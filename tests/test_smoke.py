"""MCP 冒烟测试 (ARCHITECTURE.md: tests 含 MCP 冒烟测试)。

用 fastmcp 内存 Client 直接打 create_app 产物, 不经 stdio, 验证
工具注册 / 闸门 / 基本调用链 (T1 + T5 验收)。
"""

from __future__ import annotations

import pytest
from fastmcp import Client

from plctap.config import PlctapConfig
from plctap.server import create_app

REQ_FC3 = bytes.fromhex("123400000006" "01" "03" "0000" "000A").hex()
READ_RESP = bytes.fromhex("000100000007" "01" "03" "04" "0102" "0304").hex()
EXC_RESP = bytes.fromhex("000100000003" "01" "83" "02").hex()


async def test_default_tools_registered(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        tools = {t.name for t in await client.list_tools()}
    assert {
        "list_protocols",
        "probe_device",
        "plc_read",
        "parse_frame",
        "validate_frame",
        "diagnose",
        "parse_pcap",
        "start_listener",
        "stop_listener",
        "get_listener_frames",
    } <= tools


async def test_write_tool_not_registered_by_default():
    app = create_app(PlctapConfig())
    async with Client(app) as client:
        tools = {t.name for t in await client.list_tools()}
    assert "plc_write" not in tools  # D5: 闸门关闭时 Agent 不可见
    assert "send_frame" not in tools  # 原始帧与写同闸门


async def test_write_tool_registered_when_allowed(tmp_path):
    app = create_app(
        PlctapConfig(allow_write=True, audit_log=tmp_path / "audit.jsonl")
    )
    async with Client(app) as client:
        tools = {t.name for t in await client.list_tools()}
    assert {"plc_write", "send_frame"} <= tools


async def test_list_protocols_contains_modbus(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        result = await client.call_tool("list_protocols", {})
    assert "modbus" in result.data["protocols"]


async def test_parse_frame_request(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        result = await client.call_tool("parse_frame", {"protocol": "modbus", "frame_hex": REQ_FC3})
    data = result.data
    assert data.valid
    values = {f.name: f.value for f in data.fields}
    assert values["function_code"] == 3 and values["quantity"] == 10


async def test_parse_frame_exception_response(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        result = await client.call_tool("parse_frame", {"protocol": "modbus", "frame_hex": EXC_RESP})
    by_name = {f.name: f for f in result.data.fields}
    assert by_name["exception_code"].value == 2
    assert "ILLEGAL_DATA_ADDRESS" in by_name["exception_code"].note


async def test_parse_frame_bad_hex_rejected(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        with pytest.raises(Exception, match="hex"):
            await client.call_tool("parse_frame", {"protocol": "modbus", "frame_hex": "ZZZZ"})


async def test_validate_frame_response(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        result = await client.call_tool(
            "validate_frame", {"protocol": "modbus", "frame_hex": READ_RESP, "direction": "resp"}
        )
    checks = result.data
    assert all(c.passed for c in checks)
    assert any(c.name == "length_field_consistent" for c in checks)


async def test_validate_frame_catches_corruption(tmp_path):
    broken = READ_RESP[:8] + "63" + READ_RESP[10:]  # 篡改长度字段
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        result = await client.call_tool(
            "validate_frame", {"protocol": "modbus", "frame_hex": broken, "direction": "resp"}
        )
    failed = [c.name for c in result.data if not c.passed]
    assert "length_field_consistent" in failed


async def test_unknown_protocol_rejected(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        with pytest.raises(Exception, match="unknown protocol"):
            await client.call_tool("probe_device", {"protocol": "nonexistent", "host": "1.2.3.4", "port": 102})


async def test_audit_log_written_on_write_call(tmp_path):
    """写审计不可关 (红线 2): 帧在发送前落审计, 连接失败也留痕真实帧。"""
    log = tmp_path / "audit.jsonl"
    app = create_app(
        PlctapConfig(allow_write=True, audit_log=log, default_timeout_ms=150)
    )
    async with Client(app) as client:
        # 端口 1 无从站: 帧已构建并审计, 随后连接失败
        with pytest.raises(Exception):
            await client.call_tool(
                "plc_write",
                {"protocol": "modbus", "host": "127.0.0.1", "port": 1, "address": 0, "value": 1},
            )
    text = log.read_text(encoding="utf-8")
    assert log.exists() and "plc_write" in text
    # fc06 请求帧: MBAP(7B) + 06 + addr=0000 + value=0001 -> 含 "1000000001020001"
    assert "1000000001020001" in text


def test_main_runs_stdio_without_banner(monkeypatch):
    """Windows MCP 客户端对 stderr UTF-8 敏感; FastMCP 启动横幅必须关闭。"""
    import plctap.server as server_module
    from plctap.server import main

    calls: dict[str, object] = {}

    class FakeApp:
        def run(self, **kwargs):
            calls.update(kwargs)

    monkeypatch.setattr(server_module, "create_app", lambda: FakeApp())
    main()
    assert calls == {"show_banner": False}


async def test_send_frame_roundtrip_and_audit(tmp_path):
    """send_frame: 原始帧发到 listener 收到响应; 发送前完整帧落审计 (D5)。"""
    from plctap.listener import ListenerRegistry

    log = tmp_path / "audit.jsonl"
    app = create_app(
        PlctapConfig(allow_write=True, audit_log=log, default_timeout_ms=2000)
    )
    registry = ListenerRegistry()
    info = await registry.start("modbus", "127.0.0.1", 0, "respond_normal")
    port = info["port"]
    try:
        async with Client(app) as client:
            result = await client.call_tool(
                "send_frame",
                {"protocol": "modbus", "host": "127.0.0.1", "port": port, "frame_hex": REQ_FC3},
            )
        data = result.data
        assert data.sent_frame == REQ_FC3
        assert data.received_frame  # listener 回了最小正常响应
    finally:
        await registry.stop(port)
    text = log.read_text(encoding="utf-8")
    assert "send_frame" in text and REQ_FC3 in text

# ---------------------------------------------------------------- S7 parse_frame (真实 PLC 帧)


S7_READ_REQ = "0300001F02F080320100000001000E00000401120A10020004000184005250"
S7_READ_RSP = "0300001D02F0803203000000010002001F00000401FF04000441970A3D"


async def test_parse_frame_s7_request(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        result = await client.call_tool(
            "parse_frame", {"protocol": "s7", "frame_hex": S7_READ_REQ, "direction": "req"}
        )
    data = result.data
    assert data.valid, data.errors
    values = {f.name: f.value for f in data.fields}
    assert values["function"] == 4
    assert values["item0_byte_address"] == 2634
    assert values["item0_address"] == "DB1.DBB2634"


async def test_parse_frame_s7_response_real_header(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        result = await client.call_tool(
            "parse_frame", {"protocol": "s7", "frame_hex": S7_READ_RSP, "direction": "resp"}
        )
    data = result.data
    assert data.valid, data.errors
    values = {f.name: f.value for f in data.fields}
    assert values["return_code"] == 0xFF
    assert values["word_values"] == [0x4197, 0x0A3D]


async def test_parse_frame_s7_auto_direction(tmp_path):
    app = create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    async with Client(app) as client:
        req = await client.call_tool("parse_frame", {"protocol": "s7", "frame_hex": S7_READ_REQ})
        rsp = await client.call_tool("parse_frame", {"protocol": "s7", "frame_hex": S7_READ_RSP})
    assert req.data.fields[0].name == "tpkt_version" and req.data.valid
    assert rsp.data.valid
    assert {f.name: f.value for f in rsp.data.fields}["rosctr"] == 3
