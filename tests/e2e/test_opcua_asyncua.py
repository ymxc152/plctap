"""OPC UA 端点经 MCP 工具链的 e2e (v0.6)。

进程内 asyncua server 当台架 + fastmcp 内存 Client 走完整工具链:
probe / read / browse / detect / 设计声明负例 / 元数据诚实性。
交叉验证口径: asyncua 自洽验证 (诚实声明, 非字节级权威交叉验证)。
CI 无 asyncua 时自动跳过 (asyncua 已是运行时依赖, 正常必装)。
"""

from __future__ import annotations

import logging

import pytest
from fastmcp import Client

pytest.importorskip("asyncua")

from plctap.config import PlctapConfig  # noqa: E402
from plctap.server import create_app  # noqa: E402


@pytest.fixture
async def sim():
    logging.disable(logging.CRITICAL)
    from asyncua import Server, ua

    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://127.0.0.1:0/plctap/test/")
    idx = await server.register_namespace("http://plctap.test")
    demo = await server.nodes.objects.add_folder(
        ua.NodeId("Demo", idx), ua.QualifiedName("Demo", idx)
    )
    await demo.add_variable(ua.NodeId("Demo.Double", idx), ua.QualifiedName("Double", idx), 3.1415927)
    await demo.add_variable(ua.NodeId("Demo.Array", idx), ua.QualifiedName("Array", idx), [1.0, 2.0, 3.0])
    big = await demo.add_folder(ua.NodeId("Demo.Big", idx), ua.QualifiedName("Big", idx))
    for i in range(250):
        await big.add_variable(ua.NodeId(f"Demo.Big.N{i}", idx), ua.QualifiedName(f"N{i}", idx), i)
    await server.start()
    port = server.bserver._server.sockets[0].getsockname()[1]
    yield port, idx
    await server.stop()
    logging.disable(logging.NOTSET)


def _app(tmp_path, **kw):
    return create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl", **kw))


async def test_list_protocols_honest_capabilities(tmp_path, sim):
    """闸门开启时 opcua 依旧 write/send_raw=false, browse=true (类级诚实判定)。"""
    port, _idx = sim
    async with Client(_app(tmp_path, allow_write=True)) as client:
        result = await client.call_tool("list_protocols", {})
    entry = result.data["protocols"]["opcua"]
    assert entry["write"] is False
    assert entry["send_raw"] is False
    assert entry["browse"] is True
    assert entry["addressing_model"] == "node_id"
    assert "不做帧级解析" in entry["summary"]


async def test_probe_and_read_via_tools(tmp_path, sim):
    port, idx = sim
    async with Client(_app(tmp_path)) as client:
        probe = await client.call_tool(
            "probe_device",
            {"protocol": "opcua", "host": "127.0.0.1", "port": port},
        )
        assert probe.data.reachable
        read = await client.call_tool(
            "plc_read",
            {"protocol": "opcua", "host": "127.0.0.1", "port": port,
             "address": f"ns={idx};s=Demo.Double", "count": 1},
        )
        assert read.data.interpreted == 3.1415927


async def test_plc_read_rejects_integer_address(tmp_path, sim):
    port, _idx = sim
    async with Client(_app(tmp_path)) as client:
        with pytest.raises(Exception, match="NodeId"):
            await client.call_tool(
                "plc_read",
                {"protocol": "opcua", "host": "127.0.0.1", "port": port, "address": 5},
            )


async def test_plc_browse_via_tool(tmp_path, sim):
    port, idx = sim
    async with Client(_app(tmp_path)) as client:
        root = await client.call_tool(
            "plc_browse", {"protocol": "opcua", "host": "127.0.0.1", "port": port}
        )
        assert root.data["node"] == "ns=0;i=85"  # 缺省 Objects 文件夹
        big = await client.call_tool(
            "plc_browse",
            {"protocol": "opcua", "host": "127.0.0.1", "port": port,
             "node": f"ns={idx};s=Demo.Big"},
        )
        assert big.data["total"] == 250 and big.data["shown"] == 200
        assert big.data["truncated"]
        with pytest.raises(Exception, match="browse 未实现"):
            await client.call_tool(
                "plc_browse",
                {"protocol": "modbus", "host": "127.0.0.1", "port": 502},
            )


async def test_frame_tools_declare_no_frame_level(tmp_path, sim):
    """设计声明: opcua 的帧级工具明确拒绝, 不是漏实现。"""
    port, _idx = sim
    async with Client(_app(tmp_path)) as client:
        with pytest.raises(Exception, match="不做帧级诊断"):
            await client.call_tool(
                "parse_frame", {"protocol": "opcua", "frame_hex": "00" * 8}
            )
        with pytest.raises(Exception, match="不做帧级诊断"):
            await client.call_tool(
                "validate_frame", {"protocol": "opcua", "frame_hex": "00" * 6}
            )
        with pytest.raises(Exception, match="不支持帧级证据"):
            await client.call_tool(
                "diagnose",
                {"protocol": "opcua", "frame_hex": "00" * 8},
            )


async def test_diagnose_probe_path_hits_kb(tmp_path, sim):
    """无帧诊断路径: host+port 探测 -> common 连通性条目命中。

    refused/timeout 因 OS 而异 (Windows 关端口表现为 timeout), 两者
    各有通用条目 (kb/common.yaml, protocol: any)。
    """
    async with Client(_app(tmp_path)) as client:
        report = await client.call_tool(
            "diagnose",
            {"protocol": "opcua", "host": "127.0.0.1", "port": 1},
        )
        symptoms = [c.symptom for c in report.data.candidates]
        assert any(("TCP 连接被拒绝" in s) or ("连接超时" in s) for s in symptoms)


async def test_detect_identifies_opcua(tmp_path, sim):
    """detect 对 4840 端口识别 opcua 并经 ServerArray 最小读升级 verified。"""
    port, _idx = sim
    async with Client(_app(tmp_path)) as client:
        result = await client.call_tool(
            "detect_device", {"host": "127.0.0.1", "ports": [port], "deep": True}
        )
        top = result.data.candidates[0]
        assert top.protocol == "opcua"
        assert top.confidence == "verified"
        assert top.verified_read is not None


async def test_send_frame_guard_lists_supported(tmp_path, sim):
    """闸门开启时 opcua send_frame 给出可用协议清单 (元数据诚实守卫)。"""
    port, _idx = sim
    async with Client(_app(tmp_path, allow_write=True)) as client:
        with pytest.raises(Exception, match="send_raw 未实现"):
            await client.call_tool(
                "send_frame",
                {"protocol": "opcua", "host": "127.0.0.1", "port": port,
                 "frame_hex": "00" * 8},
            )
