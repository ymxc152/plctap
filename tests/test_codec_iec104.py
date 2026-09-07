"""IEC 60870-5-104 codec 纯函数测试: 构建/解析回环, 帧型判别, 异常路径。"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.iec104 import codec


def test_apci_u_build_parse():
    f = codec.build_apci_u(codec.U_STARTDT_ACT)
    assert f == bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
    p = codec.parse_frame(f)
    assert p.valid and p.fields[2].value == "U"
    assert any(x.note == "STARTDT_ACT" for x in p.fields)


def test_apci_u_unknown_function_rejected():
    with pytest.raises(ValueError, match="unknown U-format"):
        codec.build_apci_u(0xFF)


def test_apci_s_build_parse():
    f = codec.build_apci_s(42)
    assert f[:2] == b"\x68\x04" and f[2] == 0x01
    p = codec.parse_frame(f)
    assert any(x.name == "rx_seq_confirmed" and x.value == 42 for x in p.fields)


def test_i_frame_seq_encoding():
    """发送/接收序号线上 <<1, 低 bit = 0/1 (规范图 6)。"""
    f = codec.build_apci_i(5, 9, codec.build_asdu_interrogation())
    b2, b3, b4, b5 = f[2], f[3], f[4], f[5]
    assert (b3 << 8 | b2) & 0x01 == 0  # 发送序号 LSB=0
    assert (b5 << 8 | b4) & 0x01 == 1  # 接收序号 LSB=1
    tx, rx = codec.apci_seq_i(f[2:6])
    assert (tx, rx) == (5, 9)


def test_interrogation_asdu_layout():
    """总召 ASDU: type 100 + num 1 + COT 6 (LE) + CA 1 (LE) + QOI 20, 无 IOA。"""
    a = codec.build_asdu_interrogation()
    # 与 lib60870 官方 client 发出的总召逐字节一致: 680e0000000064010600010000000014
    assert a == bytes([100, 1, 6, 0, 1, 0, 0, 0, 0, 20])
    p = codec.parse_asdu(codec.build_apci_i(0, 0, a), 6, len(a))
    assert p.valid
    fields = {f.name: f.value for f in p.fields}
    assert fields["type_id"] == 100 and fields["cot"] == 6 and fields["common_address"] == 1


def test_monitor_single_point_roundtrip():
    a = codec.build_asdu_single_point(200, True, cot=20, ca=1)
    p = codec.parse_asdu(codec.build_apci_i(0, 0, a), 6, len(a))
    assert p.valid
    fields = {f.name: f.value for f in p.fields}
    assert fields["asdu_values"] == [1]


def test_short_float_word_order():
    """M_ME_NC 短浮点: wire LE float, 解为 2 个 16 位字 [高字, 低字]。"""
    import struct as s
    bits = s.unpack("<I", s.pack("<f", 3.1415927))[0]
    a = codec.build_asdu_measured(300, bits, "nc", cot=20, ca=1)
    p = codec.parse_asdu(codec.build_apci_i(0, 0, a), 6, len(a))
    assert p.valid
    fields = {f.name: f.value for f in p.fields}
    # float32 big 解释 = [高字, 低字] 合并
    hi, lo = fields["asdu_values"]
    assert s.unpack(">f", struct.pack(">HH", hi, lo))[0] == pytest.approx(3.1415927, rel=1e-6)


def test_vsq_sequence_ioa_continuation():
    """SQ 序列: 首对象带 IOA, 后续仅元素 (每元素 1B, 8 点 = 3 + 8 字节)。"""
    a = codec.build_asdu_objects(codec.M_SP_NA_1, [(200, [1]), (201, [0]), (202, [1])], 20, 1)
    # 手工改造成 SQ 序列: vsq = 0x80|3, 对象区 = IOA3 + 元素连续 (共 3+3 字节)
    body = bytes([1, 0x83]) + a[2:6] + a[6:10] + bytes([0, 1])
    p = codec.parse_asdu(codec.build_apci_i(0, 0, bytes(body)), 6, len(body))
    assert p.valid, p.errors


def test_objects_length_mismatch_is_invalid():
    a = bytearray(codec.build_asdu_single_point(1, True, cot=20, ca=1))
    a[1] = 2  # 谎报 2 个对象
    p = codec.parse_asdu(codec.build_apci_i(0, 0, bytes(a)), 6, len(a))
    assert not p.valid and any("expected" in e for e in p.errors)


def test_start_byte_and_length_guards():
    p = codec.parse_frame(b"\x00" * 10)
    assert not p.valid and any("start byte" in e for e in p.errors)
    p = codec.parse_frame(bytes([0x68, 0xFF]) + b"\x00" * 10)
    assert not p.valid and any("out of range" in e for e in p.errors)
    p = codec.parse_frame(bytes([0x68, 0x08]) + b"\x00" * 5)  # 截断 (APDU 需 8+2=10 字节)
    assert not p.valid and any("truncated" in e for e in p.errors)


def test_validate_checklist():
    good = codec.build_apci_u(codec.U_TESTFR_CON)
    checks = {c.name: c.passed for c in codec.validate_frame(good)}
    assert checks["start_byte"] and checks["length_field"] and checks["u_function_known"]
    bad = bytes([0x68, 0x03, 0x00, 0x00, 0x00, 0x00])  # APDU 长度 < 4
    checks = {c.name: c.passed for c in codec.validate_frame(bad)}
    assert not checks["length_field"]


def test_direction_heuristic_act_con_is_resp():
    """总召 ACT -> req; ACT_CON / ACT_TERM -> resp (COT 判别)。"""
    req = codec.build_apci_i(0, 0, codec.build_asdu_interrogation(cot=6))
    assert codec.parse_frame(req).direction == "req"
    act_con = bytearray(req[6:])
    act_con[2] = 7
    resp = codec.build_apci_i(0, 1, bytes(act_con))
    assert codec.parse_frame(resp).direction == "resp"
