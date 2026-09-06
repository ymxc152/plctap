"""诊断引擎测试 (M2): kb 完整性 + 各匹配路径 + 空结果语义。"""

from __future__ import annotations

import struct

import pytest

from plctap.diag.engine import diagnose, kb_entries, kb_entry_ids
from plctap.models import ProbeResult
from plctap.protocols.fins import codec as fins_codec
from plctap.protocols.modbus.codec import build_read_request
from plctap.protocols.melsec import codec as mc_codec


# ---------------------------------------------------------------- KB 完整性


def test_kb_has_50_plus_entries():
    assert len(kb_entries()) >= 50


def test_kb_ids_unique():
    ids = kb_entry_ids()
    assert len(ids) == len(kb_entries())


@pytest.mark.parametrize("entry", kb_entries(), ids=lambda e: e["id"])
def test_kb_entry_shape(entry):
    c = entry["candidate"]
    assert c["symptom"] and c["root_cause"] and c["suggested_action"]
    assert 0 < c["confidence"] <= 1
    assert entry["protocol"] in ("modbus", "fins", "melsec", "s7", "any")
    m = entry.get("match", {})
    assert isinstance(m, dict)
    if "failure_class" in m:
        assert set(m["failure_class"]) <= {
            "connection_refused", "timeout", "connected_but_no_reply", "exception_response"
        }


# ---------------------------------------------------------------- Modbus


def test_modbus_exception_code_02():
    resp = bytes.fromhex("000100000003018302")
    r = diagnose("modbus", frames_hex=[resp.hex()])
    top = r.candidates[0]
    assert top.root_cause.startswith("起始地址或数量超出")
    assert top.confidence == 0.95
    assert any("frame[0]" in e for e in top.evidence)


def test_modbus_rtu_crc_mismatch():
    frame = bytes.fromhex("010300000001") + b"\xde\xad"  # 坏 CRC
    r = diagnose("modbus", frames_hex=[frame.hex()])
    assert any(c.symptom == "RTU 帧校验和错" for c in r.candidates)


def test_modbus_tid_mismatch():
    req = build_read_request(1, 1, 3, 0, 1)
    resp = bytes.fromhex("009900000005" + "010302" + "1234")  # tid=0x99 != 1
    r = diagnose("modbus", frames_hex=[req.hex(), resp.hex()])
    assert any(c.symptom == "响应事务号与请求不一致" for c in r.candidates)


def test_modbus_log_snippet_extraction():
    log = (
        "2026-09-04 10:00:00 INFO request sent 010300000002\n"
        "2026-09-04 10:00:00 INFO recv 0002000000030183 02\n"  # 中间有空格分隔
        "2026-09-04 10:00:01 INFO retrying\n"
    )
    r = diagnose("modbus", log_snippet=log)
    # 0002000000030183 02 连续 hex 部分 "0002000000030183" 会被提取 (16 字符)
    assert any("extracted" in o for o in r.observations)


def test_modbus_no_match_returns_empty():
    # 正常响应帧: 无候选, observations 说明知识库未覆盖原因缺失
    resp = bytes.fromhex("0001000000050103021234")
    r = diagnose("modbus", frames_hex=[resp.hex()])
    assert r.candidates == []
    assert any("no kb entry matched" in o for o in r.observations)


def test_diagnose_no_input_returns_empty_with_hint():
    # 引擎层: 空输入返回空报告 + 提示; "至少给一种证据"的校验在工具层
    r = diagnose("modbus")
    assert r.candidates == []
    assert any("no observation provided" in o for o in r.observations)


# ---------------------------------------------------------------- FINS


def fins_resp(end_code, sid=1, sa1=3):
    fins = (
        bytes([0xC0, 0x00, 0x02]) + bytes([0, 1, 0]) + bytes([0, 1, sa1]) + bytes([sid])
        + struct.pack(">H", fins_codec.CMD_MEMORY_AREA_READ)
        + struct.pack(">H", end_code)
    )
    return fins_codec.build_tcp_frame(fins_codec.TCP_CMD_EXCHANGE, fins)


def test_fins_end_code_1101():
    r = diagnose("fins", frames_hex=[fins_resp(0x1101).hex()])
    top = r.candidates[0]
    assert top.symptom == "地址超出范围"
    assert top.confidence == 0.95


def test_fins_handshake_refused_by_tcp_command():
    frame = fins_codec.build_tcp_frame(fins_codec.TCP_CMD_CONNECT_REFUSED, b"\x00" * 8)
    r = diagnose("fins", frames_hex=[frame.hex()])
    assert any(c.symptom == "PLC 回节点连接拒绝 (TCP cmd 0x02 且无 FINS 载荷)" for c in r.candidates)


def test_fins_cmd2_data_response_not_misread_as_refused():
    """回归: 主流实现的 cmd 0x02 数据交换响应 (带 FINS 载荷) 不得命中连接拒绝条目。"""
    resp = fins_codec.build_tcp_frame(
        fins_codec.TCP_CMD_DATA_SEND,
        bytes([0xC0, 0x00, 0x02]) + bytes([0x00, 1, 0x00]) + bytes([0x00, 2, 0x00])
        + bytes([1]) + struct.pack(">H", fins_codec.CMD_MEMORY_AREA_READ)
        + struct.pack(">H", 0) + b"\x00" * 4,
    )
    r = diagnose("fins", frames_hex=[resp.hex()])
    assert not any("拒绝" in c.symptom for c in r.candidates)


def test_fins_bad_magic():
    frame = b"XXXX" + fins_resp(0)[4:]
    r = diagnose("fins", frames_hex=[frame.hex()])
    assert any(c.symptom.startswith("帧头不是") for c in r.candidates)


def test_fins_sid_mismatch_cross_check():
    req = fins_codec.build_read_request(1, 1, 0x82, 0, 1, dest_node=3)
    resp = fins_resp(0, sid=9, sa1=3)
    r = diagnose("fins", frames_hex=[req.hex(), resp.hex()])
    assert any(c.symptom == "响应 SID 与请求不一致" for c in r.candidates)


def test_fins_reference_note_on_values():
    fins = (
        bytes([0xC0, 0x00, 0x02]) + bytes([0, 1, 0]) + bytes([0, 1, 1]) + bytes([1])
        + struct.pack(">H", fins_codec.CMD_MEMORY_AREA_READ)
        + struct.pack(">H", 0) + struct.pack(">H", 0x1234)
    )
    frame = fins_codec.build_tcp_frame(fins_codec.TCP_CMD_EXCHANGE, fins)
    r = diagnose("fins", frames_hex=[frame.hex()])
    assert any(o.startswith("reference:") for o in r.observations)


# ---------------------------------------------------------------- MELSEC


def test_melsec_c04f():
    data = struct.pack("<H", 0xC04F)
    header = (
        mc_codec.RESPONSE_SUBHEADER_BYTES + bytes([0, 0xFF]) + struct.pack("<H", 0x03FF)
        + bytes([0]) + struct.pack("<H", len(data))
    )
    r = diagnose("melsec", frames_hex=[(header + data).hex()])
    top = r.candidates[0]
    assert top.symptom == "软元件号超出允许范围"
    assert top.confidence == 0.95


def test_melsec_subheader_wrong():
    data = struct.pack("<H", 0) + struct.pack("<H", 0x1234)
    header = b"\x50\x50" + bytes([0, 0xFF]) + struct.pack("<H", 0x03FF) + bytes([0]) + struct.pack("<H", len(data))
    r = diagnose("melsec", frames_hex=[(header + data).hex()])
    assert any(c.symptom.startswith("副头部不是") for c in r.candidates)


# ---------------------------------------------------------------- probe


def test_probe_connection_refused():
    r = diagnose("modbus", probe_result=ProbeResult(reachable=False, failure_class="connection_refused"))
    top = r.candidates[0]
    assert top.symptom == "TCP 连接被拒绝"
    assert any("probe failure_class=connection_refused" in e for e in top.evidence)


def test_probe_timeout():
    r = diagnose("fins", probe_result=ProbeResult(reachable=False, failure_class="timeout"))
    assert r.candidates[0].symptom == "连接超时"


def test_probe_no_reply():
    r = diagnose("melsec", probe_result=ProbeResult(reachable=False, failure_class="connected_but_no_reply"))
    assert r.candidates[0].symptom.startswith("TCP 建立成功但协议层不应答")


def test_probe_and_frames_combined():
    # 探测归因 + 异常帧: 两条候选按置信度排序
    resp = bytes.fromhex("000100000003018302")
    r = diagnose(
        "modbus",
        frames_hex=[resp.hex()],
        probe_result=ProbeResult(reachable=False, failure_class="exception_response", exception_code=2),
    )
    symptoms = [c.symptom for c in r.candidates]
    assert "设备拒绝该地址段" in symptoms and "TCP 连接被拒绝" not in symptoms


def test_no_candidates_with_probe_only_non_matching():
    # probe 正常但无帧输入: probe 条目不命中, 返回空
    r = diagnose("modbus", probe_result=ProbeResult(reachable=True))
    assert r.candidates == []


# ---------------------------------------------------------------- 评测自检


def test_kb_covers_all_modbus_validate_checks():
    """M2 验收: Modbus 校验清单的每个检查项都有 KB 条目引用。"""
    check_names = {
        "mbap_header_complete", "protocol_id_zero", "length_field_consistent",
        "unit_id_in_range", "function_code_known", "exception_code_known",
        "exception_frame_exact_length", "request_pdu_valid", "response_pdu_valid",
    }
    referenced = set()
    for e in kb_entries():
        referenced.update(e.get("match", {}).get("check_failed", []))
    missing = check_names - referenced
    assert not missing, f"KB 未覆盖检查项: {missing}"
