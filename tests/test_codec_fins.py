"""FINS/TCP codec 纯函数测试 (M2)。

帧样本全部用 codec 自己的 build_* 构造 + 手工字节注入, 不含任何真实
设备报文 (红线 1)。
"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.fins import codec


def fins_read_resp(sid=1, sa1=1, end_code=0, words=(0x1234, 0xBEEF)) -> bytes:
    """构造 0101 读响应 (TCP 层 + FINS 层)。"""
    fins = (
        bytes([0xC0, 0x00, 0x02])
        + bytes([0x00, 0x01, 0x00])  # DNA DA1 DA2
        + bytes([0x00, sa1, 0x00])  # SNA SA1 SA2
        + bytes([sid])
        + struct.pack(">H", codec.CMD_MEMORY_AREA_READ)
        + struct.pack(">H", end_code)
        + b"".join(struct.pack(">H", w) for w in words)
    )
    return codec.build_tcp_frame(codec.TCP_CMD_EXCHANGE, fins)


# ---------------------------------------------------------------- build


def test_build_handshake_layout():
    frame = codec.build_handshake_request(7)
    assert frame[:4] == b"FINS"
    (length,) = struct.unpack_from(">I", frame, 4)
    assert length == 12  # command4 + error4 + payload4
    assert frame[8:12] == b"\x00\x00\x00\x00"  # connect-req
    assert frame[16:20] == struct.pack(">I", 7)


def test_build_read_request_layout():
    frame = codec.build_read_request(sid=5, client_node=1, area_code=0x82, address=100, count=3)
    # TCP 层
    assert frame[:4] == b"FINS"
    (length,) = struct.unpack_from(">I", frame, 4)
    assert length == 8 + 18  # 10B FINS 头 + cmd2 + area1 + addr3 + count2
    assert frame[8:12] == b"\x00\x00\x00\x04"
    # FINS 层
    p = frame[16:]
    assert p[0] == 0x80  # ICF: 响应要求
    assert p[4] == 0x00  # DA1 默认 0
    assert p[7] == 0x01  # SA1 = client_node
    assert p[9] == 5  # sid
    assert struct.unpack_from(">H", p, 10)[0] == 0x0101
    assert p[12] == 0x82  # DM
    assert int.from_bytes(p[13:15], "big") == 100
    assert p[15] == 0  # bit
    assert int.from_bytes(p[16:18], "big") == 3


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"sid": 0x100}, "sid"),
        ({"address": 0x10000}, "address"),
        ({"count": 0}, "count"),
        ({"count": 32767}, "count"),
        ({"area_code": 0x99}, "area code"),
    ],
)
def test_build_read_request_rejects_bad_params(kwargs, fragment):
    base = dict(sid=1, client_node=1, area_code=0x82, address=0, count=1)
    base.update(kwargs)
    with pytest.raises(ValueError, match=fragment):
        codec.build_read_request(**base)


# ---------------------------------------------------------------- parse


def test_parse_response_normal():
    frame = fins_read_resp(sid=9, sa1=3, words=[1, 2, 3])
    req = codec.build_read_request(9, 1, 0x82, 0, 3, dest_node=3)
    r = codec.parse_response(frame, request=req)
    by_name = {f.name: f for f in r.fields}
    assert by_name["end_code"].value == 0
    assert by_name["end_code"].note == "NORMAL_COMPLETION"
    assert by_name["word_values"].value == [1, 2, 3]
    # 每个字段带字节偏移证据
    assert by_name["end_code"].raw_hex == "0000"
    assert by_name["end_code"].byte_offset == codec.TCP_HEADER_LEN + codec.FINS_HEADER_LEN + 2


def test_parse_response_end_code_nonzero():
    # valid 语义是"结构合法"而非"操作成功": 非零端结码结构上仍合法
    frame = fins_read_resp(end_code=0x1101, words=[])
    r = codec.parse_response(frame)
    by_name = {f.name: f for f in r.fields}
    assert r.valid
    assert by_name["end_code"].value == 0x1101
    assert by_name["end_code"].note == "ADDRESS_RANGE_ERROR"


def test_parse_response_end_code_nonzero_with_trailing_data():
    # 端结码非 0 却带数据: 结构异常, 归入 errors
    frame = fins_read_resp(end_code=0x1101, words=[1])
    r = codec.parse_response(frame)
    assert not r.valid
    assert any("trailing data" in e for e in r.errors)


def test_parse_response_cross_check_sid_mismatch():
    req = codec.build_read_request(1, 1, 0x82, 0, 1)
    frame = fins_read_resp(sid=2, sa1=1)
    r = codec.parse_response(frame, request=req)
    assert any("sid mismatch" in e for e in r.errors)


def test_parse_response_cross_check_node_mismatch():
    req = codec.build_read_request(1, 1, 0x82, 0, 1, dest_node=7)
    frame = fins_read_resp(sid=1, sa1=3)
    r = codec.parse_response(frame, request=req)
    assert any("node mismatch" in e for e in r.errors)


def test_parse_response_bad_magic():
    r = codec.parse_response(b"XXXX" + b"\x00" * 12)
    assert not r.valid
    assert any("magic" in e.lower() or "too short" in e for e in r.errors)


def test_parse_response_truncated():
    # 手工构造"长度字段自洽但数据是奇数个字节"的帧: FINS 层奇数报错
    fins = (
        bytes([0xC0, 0x00, 0x02]) + bytes([0, 1, 0]) + bytes([0, 1, 0]) + bytes([1])
        + struct.pack(">H", codec.CMD_MEMORY_AREA_READ) + struct.pack(">H", 0)
        + b"\x12"  # 半个字
    )
    frame = codec.build_tcp_frame(codec.TCP_CMD_EXCHANGE, fins)
    r = codec.parse_response(frame)
    assert any("odd data length" in e for e in r.errors)


def test_parse_handshake_response():
    payload = struct.pack(">II", 0x0A, 0x01)
    frame = codec.build_tcp_frame(codec.TCP_CMD_CONNECT_CFM, payload)
    info = codec.parse_handshake_response(frame)
    assert info == {"server_node": 0x0A, "client_node": 0x01, "error": 0}


def test_parse_handshake_response_wrong_command():
    frame = codec.build_tcp_frame(codec.TCP_CMD_CONNECT_REFUSED, b"\x00" * 8)
    with pytest.raises(ValueError, match="expected connect-confirm"):
        codec.parse_handshake_response(frame)


def test_parse_request_0101():
    req = codec.build_read_request(3, 1, 0x82, 42, 2)
    r = codec.parse_request(req)
    assert r.valid and r.direction == "req"
    by_name = {f.name: f for f in r.fields}
    assert by_name["area_code"].value == 0x82
    assert by_name["address"].value == 42
    assert by_name["count"].value == 2
    assert by_name["sid"].value == 3


def test_parse_request_handshake():
    r = codec.parse_request(codec.build_handshake_request(5))
    assert r.valid
    by_name = {f.name: f for f in r.fields}
    assert by_name["node_number"].value == 5


# ---------------------------------------------------------------- validate


def test_validate_response_all_pass():
    frame = fins_read_resp()
    checks = codec.validate_frame(frame, "resp")
    assert all(c.passed for c in checks)
    names = {c.name for c in checks}
    assert {"tcp_header_complete", "magic_fins", "tcp_length_consistent", "tcp_command_known", "tcp_error_zero", "end_code_known"} <= names


def test_validate_bad_magic_reported():
    frame = fins_read_resp()
    bad = b"XXXX" + frame[4:]
    checks = codec.validate_frame(bad, "resp")
    by_name = {c.name: c for c in checks}
    assert not by_name["magic_fins"].passed


def test_validate_length_inconsistent_reported():
    frame = fins_read_resp()
    bad = frame + b"\x00"  # 实际字节数多 1
    checks = codec.validate_frame(bad, "resp")
    by_name = {c.name: c for c in checks}
    assert not by_name["tcp_length_consistent"].passed


def test_validate_tcp_error_nonzero_reported():
    frame = codec.build_tcp_frame(codec.TCP_CMD_CONNECT_CFM, b"\x00" * 8, error=1)
    checks = codec.validate_frame(frame, "resp")
    by_name = {c.name: c for c in checks}
    assert not by_name["tcp_error_zero"].passed


# ---------------------------------------------------------------- 方向自动判别


def test_parse_auto_exchange_request_by_icf():
    req = codec.build_read_request(1, 1, 0x82, 0, 1)
    r = codec.parse_auto("fins", req) if hasattr(codec, "parse_auto") else None
    # parse_auto 挂在 protocols.auto 上
    from plctap.protocols.auto import parse_auto

    r = parse_auto("fins", req)
    assert r.direction == "req"


def test_parse_auto_exchange_response_by_icf_bit6():
    from plctap.protocols.auto import parse_auto

    r = parse_auto("fins", fins_read_resp())
    assert r.direction == "resp"


def test_parse_auto_handshake_request_and_response():
    from plctap.protocols.auto import parse_auto

    assert parse_auto("fins", codec.build_handshake_request(1)).direction == "req"
    refused = codec.build_tcp_frame(codec.TCP_CMD_CONNECT_REFUSED, b"\x00" * 8)
    assert parse_auto("fins", refused).direction == "resp"


# ---------------------------------------------------------------- interpret


def test_interpret_float32_byteorder_roundtrip():
    from plctap.protocols.common import interpret_registers

    # 1.0 = 0x3F800000: 高字 0x3F80, 低字 0x0000
    assert interpret_registers([0x3F80, 0x0000], "float32", "big") == [pytest.approx(1.0)]
    assert interpret_registers([0x0000, 0x3F80], "float32", "little") == [pytest.approx(1.0)]


def test_interpret_rejects_unknown_datatype():
    from plctap.protocols.common import interpret_registers

    with pytest.raises(ValueError, match="datatype"):
        interpret_registers([1], "float64")
