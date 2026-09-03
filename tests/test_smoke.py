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
    assert {"list_protocols", "probe_device", "plc_read", "parse_frame", "validate_frame"} <= tools


async def test_write_tool_not_registered_by_default():
    app = create_app(PlctapConfig())
    async with Client(app) as client:
        tools = {t.name for t in await client.list_tools()}
    assert "plc_write" not in tools  # D5: 闸门关闭时 Agent 不可见


async def test_write_tool_registered_when_allowed(tmp_path):
    app = create_app(
        PlctapConfig(allow_write=True, audit_log=tmp_path / "audit.jsonl")
    )
    async with Client(app) as client:
        tools = {t.name for t in await client.list_tools()}
    assert "plc_write" in tools


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
            await client.call_tool("probe_device", {"protocol": "s7", "host": "1.2.3.4", "port": 102})


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
    # fc06 请求帧: MBAP(7B) + 06 + addr=0000 + value=0001 -> 含 "010600000001"
    assert "010600000001" in text
