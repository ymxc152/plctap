"""v0.6.1 稳定化: dict 工具收编建模后的黄金键集合锁。

键集合取自建模前 (v0.6.0) 各工具实际返回的 dict (HANDOFF 5.24 审查记录);
模型 extra="forbid" 让构造期漂移报错, 本文件再把"键集合"本身钉死 ——
改字段名/键必须同步改这里的黄金字面量, 并在 Release notes 标注 wire 变化。

wire 兼容口径: JSON 对象键序本无序, 承诺的是键集合 + 值语义, 不是字节序。
list_protocols 的 protocols 内条目为自由形态 dict (meta 条件键"缺键而非
null"), 不建模 —— 建模会把缺键变 null, wire 即变。
"""

from __future__ import annotations

import pytest

from plctap.models import (
    BrowseChild,
    BrowseResult,
    FrameRecord,
    ListProtocolsResult,
    ListenerStartResult,
    ListenerStopResult,
    ProxyStartResult,
    ProxyStopResult,
    WriteResult,
)


def test_write_result_golden():
    sample = {"request_frame": "aa", "response_frame": "bb", "elapsed_ms": 5}
    assert WriteResult(**sample).model_dump() == sample


def test_browse_result_golden():
    sample = {
        "node": "ns=0;i=85",
        "children": [
            {"node_id": "ns=2;i=1", "display_name": None, "node_class": "Variable"},
            {"node_id": "ns=2;s=Demo.Double", "display_name": "Double", "node_class": "Variable"},
        ],
        "total": 250,
        "shown": 2,
        "truncated": True,
    }
    # display_name=None 的键建模后保留 (缺键变 null 才是 wire 变化)
    assert BrowseResult(**sample).model_dump() == sample
    child = BrowseChild(**sample["children"][0])
    assert child.model_dump() == sample["children"][0]


def test_frame_record_golden():
    sample = {
        "ts": "2026-09-08T12:00:00",
        "direction": "c2s",
        "peer": "127.0.0.1:5020",
        "frame_hex": "aa",
    }
    assert FrameRecord(**sample).model_dump() == sample


def test_listener_start_stop_golden():
    start = {
        "status": "listening",
        "protocol": "modbus",
        "host": "127.0.0.1",
        "port": 50000,
        "mode": "record_only",
        "faults": [],
        "recorded": 0,
    }
    assert ListenerStartResult(**start).model_dump() == start
    stop = {"status": "stopped", "port": 50000, "mode": "record_only", "recorded": 3, "sent": 1}
    assert ListenerStopResult(**stop).model_dump() == stop


def test_proxy_start_stop_golden():
    start = {
        "status": "proxying",
        "protocol": "modbus",
        "listen_port": 50001,
        "target": "127.0.0.1:5020",
        "recorded": 0,
        "hint": "上位机改连本代理端口; get_proxy_frames 取透传帧",
    }
    assert ProxyStartResult(**start).model_dump() == start
    stop = {
        "status": "stopped",
        "port": 50001,
        "target": "127.0.0.1:5020",
        "recorded": 2,
        "c2s": 1,
        "s2c": 1,
    }
    assert ProxyStopResult(**stop).model_dump() == stop


def test_list_protocols_result_golden():
    """外层三键锁定; 内条目自由形态 dict 原样透传 (含缺键语义)。"""
    sample = {
        "protocols": {
            # 无 meta 的条目: 基础能力五键, default_port 等条件键缺席
            "modbus": {"probe": True, "read": True, "write": True, "send_raw": True, "browse": True},
            # meta 在: 条件键齐全
            "opcua": {"probe": True, "addressing_model": "node_id", "summary": "s"},
        },
        "allow_write": False,
        "hint": "hint text",
    }
    m = ListProtocolsResult(**sample)
    assert m.model_dump() == sample
    assert "default_port" not in m.protocols["modbus"]  # 缺键保持缺键, 不变 null


def test_extra_key_forbidden():
    """黄金锁: 多余键构造即报错 —— server/adapter 添键不会静默丢。"""
    with pytest.raises(Exception):
        WriteResult(**{"request_frame": "aa", "response_frame": "bb", "elapsed_ms": 1, "surprise": 1})
    with pytest.raises(Exception):
        FrameRecord(**{"ts": "t", "direction": "c2s", "peer": "p", "frame_hex": "aa", "extra": 1})
