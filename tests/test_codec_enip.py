"""EtherNet/IP (CIP) codec 纯函数测试。

关键回归: RegisterSession/ListIdentity 与 pycomm3 编码逐字节一致
(sender context 非零 —— 全零 context 是 cpppo 等实现的互操作雷区)。
"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.enip import codec


def test_register_session_layout():
    f = codec.build_register_session()
    # 与 pycomm3 RegisterSessionRequestPacket.build_request 输出逐字节一致
    # (sender context 用 plctap 标识, 非 pycomm3 的 _pycomm_)
    assert f[:4] == b"\x65\x00\x04\x00"
    assert f[4:8] == b"\x00\x00\x00\x00"  # session 0
    assert f[8:12] == b"\x00\x00\x00\x00"  # status 0
    assert f[12:20] == b"plctap\x00\x00"  # 非零 sender context
    assert f[24:] == b"\x01\x00\x00\x00"  # protocol version 1 + options 0
    assert f[20:24] == b"\x00\x00\x00\x00"  # options


def test_parse_register_session_response():
    frame = codec.build_enip(codec.CMD_REGISTER_SESSION,
                             struct.pack("<HH", 1, 0), session=0x1234)
    assert codec.parse_register_session_response(frame) == 0x1234


def test_register_session_status_error():
    frame = bytearray(codec.build_enip(codec.CMD_REGISTER_SESSION,
                                       struct.pack("<HH", 1, 0)))
    frame[8:12] = struct.pack("<I", 0x69)  # unsupported revision
    with pytest.raises(ValueError, match="UNSUPPORTED_PROTOCOL_REVISION"):
        codec.parse_register_session_response(bytes(frame))


def test_list_identity_roundtrip():
    # 构造一个标准身份项: vendor=1 (Rockwell), product "plctap-fixture"
    ident = (
        struct.pack("<H", 1)  # encap version
        + b"\x00" * 16  # sockaddr
        + struct.pack("<I", 1)  # vendor Rockwell
        + struct.pack("<H", 12)  # product type: communication adapter
        + struct.pack("<H", 66)  # product code
        + bytes([1, 5])  # revision 1.5
        + struct.pack("<H", 0)  # status
        + struct.pack("<I", 0xDEADBEEF)  # serial
        + bytes([14]) + b"plctap-fixture"  # product name
    )
    payload = struct.pack("<H", 1) + struct.pack("<HH", codec.ITEM_CIP_IDENTITY, len(ident)) + ident
    frame = codec.build_enip(codec.CMD_LIST_IDENTITY, payload)
    info = codec.parse_list_identity_response(frame)
    assert info["vendor_id"] == 1
    assert info["product_name"] == "plctap-fixture"
    assert info["serial"] == 0xDEADBEEF


def test_tag_path_symbol_and_element():
    assert codec.build_tag_path("beta") == b"\x91\x04" + b"beta"
    # 奇数长度补齐偶数
    assert codec.build_tag_path("alpha") == b"\x91\x05" + b"alpha\x00"
    assert codec.build_tag_path("alpha[0]") == b"\x91\x05" + b"alpha\x00" + b"\x28\x00"
    assert codec.build_tag_path("alpha[7]") == b"\x91\x05" + b"alpha\x00" + b"\x28\x07"
    with pytest.raises(ValueError, match="single-dimension"):
        codec.build_tag_path("alpha[2,3]")
    with pytest.raises(ValueError, match="structure member"):
        codec.build_tag_path("motor.speed")


def test_read_tag_request_layout():
    r = codec.build_read_tag("alpha[0]", 2)
    # service + 路径字长 (10 字节路径 = 5 字) + 路径 + count
    assert r[0] == 0x4C and r[1] == 0x05
    assert r[2:12] == b"\x91\x05" + b"alpha\x00" + b"\x28\x00"
    assert r.endswith(struct.pack("<H", 2))


def test_unconnected_send_envelope():
    embedded = codec.build_read_tag("alpha[0]", 1)
    u = codec.build_unconnected_send(embedded)
    assert u[0] == 0x52
    assert struct.unpack_from("<H", u, 1)[0] == len(embedded)
    assert u[3:3 + len(embedded)] == embedded
    # 路径: 背板 1 / 槽 0 (1 字 + 补齐)
    assert u[3 + len(embedded):] == b"\x01\x01\x00\x00"


def test_send_rr_data_structure():
    session = 0x11223344
    cip = codec.build_read_tag("beta", 1)
    f = codec.build_send_rr_data(session, cip)
    assert f[:2] == b"\x6f\x00"
    assert f[4:8] == struct.pack("<I", session)
    iface, timeout, nitems = struct.unpack_from("<IHH", f, 24)
    assert (iface, timeout, nitems) == (0, 0, 2)
    addr_type, addr_len = struct.unpack_from("<HH", f, 32)
    assert (addr_type, addr_len) == (codec.ITEM_ADDRESS_NULL, 0)
    data_type, _data_len = struct.unpack_from("<HH", f, 36)
    assert data_type == codec.ITEM_CIP_UNCONNECTED_REQUEST


def test_tag_reply_success_and_status():
    # 读应答: 头 4B (service/reserved/status/addl_size) + REAL (0xCA) + 数据 (无元素数)
    bits = struct.unpack("<I", struct.pack("<f", 0.25))[0]
    cip = bytes([codec.SVC_READ_TAG_REPLY, 0x00, 0x00, 0x00]) + \
        struct.pack("<H", 0xCA) + struct.pack("<HH", bits & 0xFFFF, bits >> 16)
    p = codec.parse_tag_reply(cip, codec.SVC_READ_TAG)
    assert p.valid
    fields = {f.name: f.value for f in p.fields}
    lo, hi = fields["word_values"]  # CIP 数据区小端: [低字, 高字]
    val = struct.unpack("<f", struct.pack("<HH", lo, hi))[0]
    assert val == pytest.approx(0.25)


def test_tag_reply_cip_status_error():
    cip = bytes([codec.SVC_READ_TAG_REPLY, 0x00, 0x05, 0x00, 0x00])  # PATH_DESTINATION_UNKNOWN
    p = codec.parse_tag_reply(cip, codec.SVC_READ_TAG)
    assert not p.valid
    assert any("PATH_DESTINATION_UNKNOWN" in e for e in p.errors)


def test_write_tag_request_layout():
    w = codec.build_write_tag("beta", 0xCA, [0x0000, 0x3E80])  # REAL 0.25 的两字
    assert w[0] == 0x4D
    assert b"\x91\x04beta" in w
    assert struct.pack("<HH", 0xCA, 1) in w
    assert w.endswith(struct.pack("<HH", 0x0000, 0x3E80))
    with pytest.raises(ValueError, match="unsupported type code"):
        codec.build_write_tag("x", 0xBEEF, [1])


def test_parse_request_embedded_read():
    session = 0x11223344
    f = codec.build_send_rr_data(
        session, codec.build_unconnected_send(codec.build_read_tag("alpha[0]", 3))
    )
    p = codec.parse_request(f)
    assert p.valid
    fields = {x.name: x.value for x in p.fields}
    assert fields["tag_name"] == "alpha"
    assert fields["element_index"] == 0
    assert fields["element_count"] == 3


def test_parse_response_list_identity_status_error():
    f = bytearray(codec.build_list_identity())
    f[8:12] = struct.pack("<I", 0x01)
    p = codec.parse_response(bytes(f))
    assert not p.valid and any("INVALID_COMMAND" in e or "0x01" in e for e in p.errors)


def test_parse_request_embedded_length_overdeclared():
    """畸形 (fuzz 同源): Unconnected Send 声明的嵌入长度超过实际载荷 ——
    不得产出负长度伪字段 (route_path 无从解出), 转结构化 errors 且 valid=False。"""
    u = bytearray(codec.build_unconnected_send(codec.build_read_tag("alpha[0]", 1)))
    declared = struct.unpack_from("<H", u, 1)[0]
    struct.pack_into("<H", u, 1, declared + 8)  # 声明 8 字节并不存在的嵌入载荷
    f = codec.build_send_rr_data(0x11223344, bytes(u))
    p = codec.parse_request(f)
    assert p.valid is False
    assert any("shorter than declared" in e for e in p.errors)
    assert not any(x.name == "route_path" for x in p.fields)

