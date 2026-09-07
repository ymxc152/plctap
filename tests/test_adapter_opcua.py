"""OPC UA 适配器单测 (v0.6): 进程内 asyncua server 当台架。

交叉验证口径: asyncua client 对 asyncua server 属自洽验证 (诚实声明,
区别于其他端点的字节级权威实现交叉验证 —— 见 e2e/test_opcua_asyncua.py)。
"""

from __future__ import annotations

import json
import logging

import pytest

pytest.importorskip("asyncua")

from plctap.config import PlctapConfig  # noqa: E402
from plctap.conn.manager import ConnectionPool  # noqa: E402
from plctap.models import Target  # noqa: E402
from plctap.protocols.base import ProtocolAdapter  # noqa: E402
from plctap.protocols.opcua.adapter import (  # noqa: E402
    _BROWSE_MAX_CHILDREN,
    OpcuaAdapter,
)

NS_URI = "http://plctap.test"


@pytest.fixture
async def sim():
    """进程内 asyncua server (端口 0), 返回 (port, ns_idx)。

    连接日志会淹没 pytest 输出, 台架期间全局静音。
    """
    logging.disable(logging.CRITICAL)
    from asyncua import Server, ua

    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://127.0.0.1:0/plctap/test/")
    idx = await server.register_namespace(NS_URI)
    demo = await server.nodes.objects.add_folder(
        ua.NodeId("Demo", idx), ua.QualifiedName("Demo", idx)
    )
    await demo.add_variable(ua.NodeId("Demo.Boolean", idx), ua.QualifiedName("Boolean", idx), True)
    await demo.add_variable(ua.NodeId("Demo.Double", idx), ua.QualifiedName("Double", idx), 3.1415927)
    await demo.add_variable(ua.NodeId("Demo.String", idx), ua.QualifiedName("String", idx), "hello plctap")
    await demo.add_variable(ua.NodeId("Demo.Array", idx), ua.QualifiedName("Array", idx), [1.0, 2.0, 3.0])
    big = await demo.add_folder(ua.NodeId("Demo.Big", idx), ua.QualifiedName("Big", idx))
    for i in range(_BROWSE_MAX_CHILDREN + 50):  # 250 > 200 上限, 钉住截断
        await big.add_variable(
            ua.NodeId(f"Demo.Big.N{i}", idx), ua.QualifiedName(f"N{i}", idx), i
        )
    await server.start()
    port = server.bserver._server.sockets[0].getsockname()[1]
    yield port, idx
    await server.stop()
    logging.disable(logging.NOTSET)


@pytest.fixture
def adapter():
    return OpcuaAdapter(ConnectionPool(), PlctapConfig())


def _target(port: int) -> Target:
    return Target(protocol="opcua", host="127.0.0.1", port=port)


# ---------------------------------------------------------------- probe


async def test_probe_reachable_with_identity(sim, adapter):
    port, _idx = sim
    p = await adapter.probe(_target(port))
    assert p.reachable and p.failure_class is None
    assert p.identity["security_policy"] == "SecurityPolicyNone"
    assert p.identity["server_array"]  # 规范强制节点可读


async def test_probe_connection_refused(adapter, monkeypatch):
    """refused 归因: monkeypatch _connect (Windows 上关端口表现为 timeout,
    refused 分支需确定性注入 —— 同 M1 联测记录)。"""

    async def _refused(self, target, timeout):
        raise ConnectionRefusedError()

    monkeypatch.setattr(OpcuaAdapter, "_connect", _refused)
    p = await adapter.probe(_target(1))
    assert not p.reachable
    assert p.failure_class == "connection_refused"


async def test_browse_and_read_share_lock_semantics(sim, adapter):
    """并发 read/browse 同目标: 目标级锁串行化, 全部成功。"""
    port, idx = sim
    import asyncio

    results = await asyncio.gather(
        adapter.read(_target(port), f"ns={idx};s=Demo.Double", 1),
        adapter.browse(_target(port), node=f"ns={idx};s=Demo", limit=10),
        adapter.read(_target(port), f"ns={idx};s=Demo.String", 1),
    )
    assert results[0].interpreted == 3.1415927
    assert len(results[1]["children"]) == 5
    assert results[2].interpreted == "hello plctap"


# ---------------------------------------------------------------- read


async def test_read_scalar_native_type(sim, adapter):
    port, idx = sim
    r = await adapter.read(_target(port), f"ns={idx};s=Demo.Double", 1)
    assert r.interpreted == 3.1415927
    assert r.raw_registers == []  # 会话协议无 16 位寄存器语义
    assert "no frame-level diagnosis" in r.request_frame
    assert r.address == f"ns={idx};s=Demo.Double"


async def test_read_array_count_truncates(sim, adapter):
    port, idx = sim
    r = await adapter.read(_target(port), f"ns={idx};s=Demo.Array", 2)
    assert r.interpreted == [1.0, 2.0]
    r0 = await adapter.read(_target(port), f"ns={idx};s=Demo.Array", 0)
    assert r0.interpreted == [1.0, 2.0, 3.0]  # count=0 = 全部


async def test_read_bad_node_structured_error(sim, adapter):
    port, _idx = sim
    with pytest.raises(Exception, match="BadNodeIdUnknown"):
        await adapter.read(_target(port), "ns=9;s=Nope", 1)


async def test_read_rejects_non_string_address(adapter):
    with pytest.raises(ValueError, match="NodeId"):
        await adapter.read(_target(1), 0, 1)


# ---------------------------------------------------------------- browse


async def test_browse_children_shape(sim, adapter):
    port, idx = sim
    b = await adapter.browse(_target(port), node=f"ns={idx};s=Demo", limit=200)
    assert b["node"] == f"ns={idx};s=Demo"
    assert b["total"] == 5 and not b["truncated"]
    names = {c["display_name"] for c in b["children"]}
    assert names == {"Boolean", "Double", "String", "Array", "Big"}
    # add_folder 建的是 FolderType 的 Object 节点, 变量是 Variable
    assert all(c["node_class"] in ("Variable", "Object") for c in b["children"])


async def test_browse_budget_truncation(sim, adapter):
    port, idx = sim
    b = await adapter.browse(_target(port), node=f"ns={idx};s=Demo.Big", limit=999)
    assert b["total"] == _BROWSE_MAX_CHILDREN + 50
    assert b["shown"] == _BROWSE_MAX_CHILDREN  # 硬上限 200, limit=999 被钳制
    assert b["truncated"]


async def test_browse_output_size_budget(sim, adapter):
    """200 子节点序列化 ~17KB, 预算 32KB —— MCP token 预算上限。"""
    port, idx = sim
    b = await adapter.browse(_target(port), node=f"ns={idx};s=Demo.Big")
    assert len(json.dumps(b, ensure_ascii=False)) <= 32 * 1024


async def test_browse_bad_node_returns_empty(sim, adapter):
    """UA Browse 对不存在节点返回空引用集 (规范行为), 不抛错 —— 与 read
    的 BadNodeIdUnknown 不同 (read 是属性读, browse 是引用遍历)。"""
    port, _idx = sim
    b = await adapter.browse(_target(port), node="ns=9;s=Nope", limit=10)
    assert b["total"] == 0 and b["children"] == [] and not b["truncated"]


# ---------------------------------------------------------------- 元数据诚实


def test_write_and_send_raw_not_overridden():
    """只读协议: 不覆写 write/send_raw, 元数据类级比较如实上报 False。"""
    assert OpcuaAdapter.write is ProtocolAdapter.write
    assert OpcuaAdapter.send_raw is ProtocolAdapter.send_raw
    assert OpcuaAdapter.browse is not ProtocolAdapter.browse
