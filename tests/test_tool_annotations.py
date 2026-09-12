"""工具 annotations 黄金锁: 17 个工具的 MCP hint 值逐工具锁定。

fastmcp 出线 camelCase (readOnlyHint/destructiveHint/idempotentHint/openWorldHint);
这里锁 wire 形状 = ToolAnnotations.model_dump(by_alias=True, exclude_none=True)。
改任何 hint 值 = 元数据 wire 变化: 必须同步 server.py 的 _ANN_* 分组与这里的
黄金表, 并在 Release notes 标注。双向覆盖: 注册集合 == 黄金键集合, 新增工具
不登记 annotations 直接挂测试 (分组语义见 server.py _ANN_* 注释)。
"""

from __future__ import annotations

from fastmcp import Client

from plctap.config import PlctapConfig
from plctap.server import create_app

_GOLDEN: dict[str, dict] = {
    # 纯本地解析 (封闭世界只读)
    "list_protocols": {"readOnlyHint": True, "openWorldHint": False},
    "parse_frame": {"readOnlyHint": True, "openWorldHint": False},
    "validate_frame": {"readOnlyHint": True, "openWorldHint": False},
    "parse_pcap": {"readOnlyHint": True, "openWorldHint": False},
    # 联网只读 (探测/读/浏览/诊断/取帧)
    "probe_device": {"readOnlyHint": True, "openWorldHint": True},
    "plc_read": {"readOnlyHint": True, "openWorldHint": True},
    "plc_browse": {"readOnlyHint": True, "openWorldHint": True},
    "diagnose": {"readOnlyHint": True, "openWorldHint": True},
    "detect_device": {"readOnlyHint": True, "openWorldHint": True},
    "get_listener_frames": {"readOnlyHint": True, "openWorldHint": True},
    "get_proxy_frames": {"readOnlyHint": True, "openWorldHint": True},
    # 监听/代理生命周期 (状态变更、非破坏、非幂等)
    "start_listener": {
        "readOnlyHint": False, "destructiveHint": False,
        "idempotentHint": False, "openWorldHint": True,
    },
    "stop_listener": {
        "readOnlyHint": False, "destructiveHint": False,
        "idempotentHint": False, "openWorldHint": True,
    },
    "start_proxy": {
        "readOnlyHint": False, "destructiveHint": False,
        "idempotentHint": False, "openWorldHint": True,
    },
    "stop_proxy": {
        "readOnlyHint": False, "destructiveHint": False,
        "idempotentHint": False, "openWorldHint": True,
    },
}
_GOLDEN_WRITE: dict[str, dict] = {
    # 写类 (危险、非幂等; 默认不注册, 闸门内)
    "plc_write": {
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": False, "openWorldHint": True,
    },
    "send_frame": {
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": False, "openWorldHint": True,
    },
}


async def _list_annotations(app) -> dict:
    async with Client(app) as client:
        return {t.name: t.annotations for t in await client.list_tools()}


async def test_default_app_annotations_golden(tmp_path):
    anns = await _list_annotations(
        create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))
    )
    # 双向覆盖: 注册集合 == 黄金键集合
    assert set(anns) == set(_GOLDEN)
    for name, expected in _GOLDEN.items():
        assert anns[name] is not None, f"{name}: annotations 缺失"
        wire = anns[name].model_dump(by_alias=True, exclude_none=True)
        assert wire == expected, f"{name}: {wire} != {expected}"


async def test_write_tools_annotations_when_allowed(tmp_path):
    app = create_app(
        PlctapConfig(allow_write=True, audit_log=tmp_path / "audit.jsonl")
    )
    anns = await _list_annotations(app)
    assert set(anns) == set(_GOLDEN) | set(_GOLDEN_WRITE)
    for name, expected in _GOLDEN_WRITE.items():
        wire = anns[name].model_dump(by_alias=True, exclude_none=True)
        assert wire == expected, f"{name}: {wire} != {expected}"
