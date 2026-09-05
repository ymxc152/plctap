"""Siemens S7comm codec 纯函数测试 + 冒烟测试。"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.s7 import codec


# ---------------------------------------------------------------- COTP


def test_build_cotp_connect_request():
    cr = codec.build_cotp_connect_request(rack=0, slot=1)
    assert len(cr) == 22  # COTP CR must be exactly 22 bytes
    assert cr[0] == 3  # TPKT version
    assert cr[5] == codec.COTP_CR_PDU_TYPE  # CR
    # Remote TSAP: rack=0, slot=1 -> 0x0101
    remote_tsap = struct.unpack(">H", cr[20:22])[0]
    assert remote_tsap == 0x0101


def test_build_cotp_connect_request_rack_slot():
    cr = codec.build_cotp_connect_request(rack=0, slot=2)
    remote_tsap = struct.unpack(">H", cr[20:22])[0]
    assert remote_tsap == 0x0100 | (0 << 5) | 2  # 0x0102


# ---------------------------------------------------------------- PDU negotiation


def test_build_pdu_negotiation():
    neg = codec.build_pdu_negotiation(480)
    assert neg[0] == 3  # TPKT version
    assert neg[7] == codec.S7_PROTOCOL_ID  # 0x32
    assert struct.unpack(">H", neg[23:25])[0] == 480  # PDU length (request)


# ---------------------------------------------------------------- read


def test_build_read_request_db():
    req = codec.build_read_request("DB", 1, 0, 2, pdu_ref=1)
    assert req[0] == 3  # TPKT version
    assert req[7] == codec.S7_PROTOCOL_ID  # 0x32
    assert req[8] == codec.ROSCR_JOB
    assert req[17] == codec.FUNC_READ_VAR  # 0x04
    # Area code for DB = 0x84
    assert req[27] == 0x84
    # DB number = 1
    assert struct.unpack_from(">H", req, 25)[0] == 1
    # PDU ref = 1
    assert struct.unpack_from(">H", req, 11)[0] == 1


def test_build_read_request_m_area():
    req = codec.build_read_request("M", 0, 0, 2, pdu_ref=2)
    assert req[27] == codec.AREA_CODES["M"]  # 0x83


def test_build_read_request_invalid_area():
    with pytest.raises(ValueError, match="unknown S7 area"):
        codec.build_read_request("XX", 0, 0, 1, pdu_ref=1)


# ---------------------------------------------------------------- read response


def _make_read_resp(pdu_ref=1, rc=0xFF, words=(0x1234, 0xBEEF)):
    """构造标准 S7 Read Var Ack_Data 响应帧 (12B 头, 含 error class/code)。"""
    # Data section: return_code + transport_size + length(BE, bits) + payload
    data = bytes([rc, 0x04]) + struct.pack(">H", len(words) * 2)
    data += b"".join(struct.pack(">H", w) for w in words)

    # S7 Ack_Data header (12B)
    s7 = (
        bytes([codec.S7_PROTOCOL_ID, codec.ROSCR_ACK_DATA])
        + struct.pack(">HH", 0, pdu_ref)  # redundancy, pdu_ref
        + struct.pack(">HH", 2, len(data))  # param_len=2, data_len
        + bytes([0x00, 0x00])  # error_class, error_code
        + bytes([codec.FUNC_READ_VAR, 0x01])  # function, item_count
    )

    body = s7 + data
    tpkt = struct.pack(">BBH", 3, 0, 4 + 3 + len(body))  # TPKT + COTP(3) + body
    cotp = bytes([2, codec.COTP_DATA_PDU_TYPE, 0x80])
    return tpkt + cotp + body


def test_parse_read_response_normal():
    resp = _make_read_resp(pdu_ref=1, words=[0x1234, 0xBEEF])
    req = codec.build_read_request("DB", 1, 0, 2, pdu_ref=1)
    r = codec.parse_read_response(resp, request=req)
    assert r.valid, r.errors
    by_name = {f.name: f for f in r.fields}
    assert by_name["return_code"].value == 0xFF
    assert by_name["word_values"].value == [0x1234, 0xBEEF]


def test_parse_read_response_bad_rc():
    resp = _make_read_resp(rc=0x05)
    r = codec.parse_read_response(resp)
    assert not r.valid
    assert any("ADDRESS_OUT_OF_RANGE" in e for e in r.errors)


def test_parse_read_response_pdu_ref_mismatch():
    resp = _make_read_resp(pdu_ref=99)
    req = codec.build_read_request("DB", 1, 0, 2, pdu_ref=1)
    r = codec.parse_read_response(resp, request=req)
    assert any("pdu_reference mismatch" in e for e in r.errors)


# ---------------------------------------------------------------- write


def test_build_write_request():
    req = codec.build_write_request("DB", 1, 0, [0x1234, 0xBEEF], pdu_ref=1)
    assert req[0] == 3
    assert req[7] == codec.S7_PROTOCOL_ID
    assert req[8] == codec.ROSCR_JOB
    assert req[17] == codec.FUNC_WRITE_VAR  # 0x05
    assert req[27] == codec.AREA_CODES["DB"]  # 0x84


def test_parse_write_response():
    resp = _make_read_resp(pdu_ref=1, rc=0xFF)
    result = codec.parse_write_response(resp)
    assert result["ok"]


# ---------------------------------------------------------------- validate


def test_validate_request():
    req = codec.build_read_request("DB", 1, 0, 2, pdu_ref=1)
    checks = codec.validate_frame(req, "req")
    by_name = {c.name: c for c in checks}
    assert by_name["s7_protocol_id"].passed
    assert by_name["rosctr"].passed


def test_validate_response():
    resp = _make_read_resp()
    checks = codec.validate_frame(resp, "resp")
    by_name = {c.name: c for c in checks}
    assert by_name["s7_protocol_id"].passed
    assert by_name["rosctr"].passed
    assert by_name["return_code"].passed


def test_parse_read_response_legacy_10byte_header():
    """兼容部分模拟器/IoTClient 的 10B Ack_Data 头 (无 error class/code)。"""
    data = bytes([0x00, 0x00, 0xFF, 0x04]) + struct.pack(">H", 2)
    data += struct.pack(">H", 0xABCD)
    s7 = (
        bytes([codec.S7_PROTOCOL_ID, codec.ROSCR_ACK_DATA])
        + struct.pack(">HH", 0, 1)
        + struct.pack(">HH", 2, len(data))
        + bytes([codec.FUNC_READ_VAR, 0x01])
    )
    tpkt = struct.pack(">BBH", 3, 0, 4 + 3 + len(s7) + len(data))
    resp = tpkt + bytes([2, codec.COTP_DATA_PDU_TYPE, 0x80]) + s7 + data
    r = codec.parse_read_response(resp)
    assert r.valid, r.errors


# ---------------------------------------------------------------- real-world frames (12B Ack header)


def test_parse_request_read_roundtrip_bit_address():
    """位地址还原: DB1 字节 2634 -> 0x005250 (2634*8)。"""
    req = codec.build_read_request("DB", 1, 2634, 4, pdu_ref=1)
    r = codec.parse_request(req)
    assert r.valid, r.errors
    by_name = {f.name: f for f in r.fields}
    assert by_name["function"].value == codec.FUNC_READ_VAR
    assert by_name["pdu_reference"].value == 1
    assert by_name["item0_db_number"].value == 1
    assert by_name["item0_byte_address"].value == 2634
    assert by_name["item0_address"].value == "DB1.DBB2634"


def test_parse_request_m_area_roundtrip():
    req = codec.build_read_request("M", 0, 100, 2, pdu_ref=7)
    r = codec.parse_request(req)
    by_name = {f.name: f for f in r.fields}
    assert by_name["item0_area"].value == "0x83"
    assert by_name["item0_byte_address"].value == 100
    assert by_name["item0_address"].value == "M100"


def test_parse_request_negotiation():
    req = codec.build_pdu_negotiation(480)
    r = codec.parse_request(req)
    assert r.valid, r.errors
    by_name = {f.name: f for f in r.fields}
    assert by_name["function"].value == 0xF0
    assert by_name["pdu_length_requested"].value == 480


def test_parse_request_truncated_item_not_raise():
    req = codec.build_read_request("DB", 1, 0, 2, pdu_ref=1)[:-4]
    r = codec.parse_request(req)
    assert not r.valid
    assert r.errors  # 截断被记录为 errors 而非抛异常


def test_parse_read_response_real_plc_12b_header():
    """真实 PLC 帧Ack_Data 12B 头, param 从 19 起。"""
    rsp = bytes.fromhex("0300001D02F0803203000000010002001F00000401FF04000441970A3D")
    req = codec.build_read_request("DB", 1, 2634, 4, pdu_ref=1)
    r = codec.parse_read_response(rsp, request=req)
    assert r.valid, r.errors
    by_name = {f.name: f for f in r.fields}
    assert by_name["function"].value == codec.FUNC_READ_VAR
    assert by_name["error_class"].value == 0
    assert by_name["error_code"].value == 0
    assert by_name["return_code"].value == 0xFF
    assert by_name["transport_size"].value == 4
    assert by_name["word_values"].value == [0x4197, 0x0A3D]


def test_parse_read_response_10b_variant_still_works():
    """测试台架/echo server 的 10B Ack 头变体 (param 从 17 起)。"""
    rsp = _make_read_resp(pdu_ref=1, words=[0x1234, 0xBEEF])
    r = codec.parse_read_response(rsp)
    assert r.valid, r.errors
    by_name = {f.name: f for f in r.fields}
    assert by_name["return_code"].value == 0xFF
    assert by_name["word_values"].value == [0x1234, 0xBEEF]


def test_validate_frame_real_plc_response():
    rsp = bytes.fromhex("0300001D02F0803203000000010002001F00000401FF04000441970A3D")
    checks = codec.validate_frame(rsp, "resp")
    by_name = {c.name: c for c in checks}
    assert by_name["function_valid"].passed
    assert by_name["return_code"].passed

# ---------------------------------------------------------------- db_number 解析


def test_resolve_db_number_db_default():
    from plctap.protocols.s7.adapter import _resolve_db_number

    assert _resolve_db_number("DB", {}) == 1
    assert _resolve_db_number("DB", {"db_number": 5}) == 5


def test_resolve_db_number_non_db_defaults_zero():
    from plctap.protocols.s7.adapter import _resolve_db_number

    for area in ("M", "I", "Q"):
        assert _resolve_db_number(area, {}) == 0


def test_resolve_db_number_non_db_rejects_explicit():
    # 回归: area=M 显式/默认漏传 db_number 曾静默发出 db=1 帧导致读错数据
    from plctap.protocols.s7.adapter import _resolve_db_number

    with pytest.raises(ValueError, match="db_number"):
        _resolve_db_number("M", {"db_number": 1})
