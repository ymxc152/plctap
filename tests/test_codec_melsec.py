"""MELSEC MC 3E 二进制 codec 纯函数测试 (M2)。帧样本全部自构造。"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.melsec import codec
from plctap.protocols.auto import parse_auto


def mc_read_resp(words=(0x1234, 0xBEEF), end_code=0, net=0, pc=0, io=0x03FF, station=0) -> bytes:
    """构造 0401 读响应 (小端)。"""
    data = struct.pack("<H", end_code) + b"".join(struct.pack("<H", w) for w in words)
    header = (
        codec.SUBHEADER_BYTES
        + bytes([net, pc])
        + struct.pack("<H", io)
        + bytes([station])
        + struct.pack("<H", 0)  # timer
        + struct.pack("<H", len(data))
    )
    return header + data


# ---------------------------------------------------------------- build


def test_build_read_request_layout():
    frame = codec.build_read_request("D", 100, 2)
    assert frame[0:2] == b"\x00\x50"
    (data_len,) = struct.unpack_from("<H", frame, 9)
    assert data_len == 10  # cmd2 + subcmd2 + code1 + head3 + count2
    data = frame[codec.FRAME_HEADER_LEN:]
    assert struct.unpack_from("<H", data, 0)[0] == 0x0401
    assert data[4] == 0x44  # 'D'
    assert data[5:8] == bytes([100, 0, 0])  # 3B 小端
    assert struct.unpack_from("<H", data, 8)[0] == 2


def test_build_bit_device_count():
    frame = codec.build_read_request("X", 0, 16)
    data = frame[codec.FRAME_HEADER_LEN:]
    assert data[4] == 0x58  # 'X'
    assert struct.unpack_from("<H", data, 8)[0] == 16  # 点数原样, 响应按字回


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"device": "Z"}, "unknown device"),
        ({"head_device": 0x1000000}, "head_device"),
        ({"device_count": 0}, "device_count"),
        ({"device_count": 961}, "device_count"),
        ({"timer": 5}, "timer"),
        ({"network": 256}, "network"),
    ],
)
def test_build_read_request_rejects_bad_params(kwargs, fragment):
    base = dict(device="D", head_device=0, device_count=1)
    base.update(kwargs)
    with pytest.raises(ValueError, match=fragment):
        codec.build_read_request(**base)


# ---------------------------------------------------------------- parse


def test_parse_response_normal():
    req = codec.build_read_request("D", 0, 2)
    resp = mc_read_resp(words=[0x1234, 0xBEEF])
    r = codec.parse_response(resp, request=req)
    assert r.valid and r.direction == "resp"
    by_name = {f.name: f for f in r.fields}
    assert by_name["end_code"].value == 0
    assert by_name["word_values"].value == [0x1234, 0xBEEF]  # 小端还原
    assert by_name["word_values"].byte_offset == codec.FRAME_HEADER_LEN + 2


def test_parse_response_little_endian_semantics():
    # 线上 "34 12" 是小端的 0x1234 —— 与 FINS/Modbus 的大端相反 (知识库素材)
    resp = mc_read_resp(words=[0x1234])
    offset = codec.FRAME_HEADER_LEN + 2
    assert resp[offset : offset + 2] == b"\x34\x12"


def test_parse_response_end_code_nonzero():
    # valid 语义是"结构合法": 非零结束代码不改变结构合法性
    resp = mc_read_resp(words=[], end_code=0xC04F)
    r = codec.parse_response(resp)
    by_name = {f.name: f for f in r.fields}
    assert r.valid
    assert by_name["end_code"].value == 0xC04F
    assert by_name["end_code"].note == "DEVICE_NUMBER_OUT_OF_RANGE"


def test_parse_response_header_echo_cross_check():
    req = codec.build_read_request("D", 0, 1, network=3, pc=5, module_io=0x03FF)
    resp = mc_read_resp(net=3, pc=6)  # pc 回显错
    r = codec.parse_response(resp, request=req)
    assert any("pc_number mismatch" in e for e in r.errors)


def test_parse_response_data_short_vs_request():
    req = codec.build_read_request("D", 0, 5)
    resp = mc_read_resp(words=[1, 2])  # 少回 3 个字
    r = codec.parse_response(resp, request=req)
    assert any("data short" in e for e in r.errors)


def test_parse_request_normal():
    req = codec.build_read_request("D", 100, 2)
    r = codec.parse_request(req)
    assert r.valid and r.direction == "req"
    by_name = {f.name: f for f in r.fields}
    assert by_name["device_code"].value == 0x44
    assert by_name["head_device"].value == 100
    assert by_name["device_count"].value == 2


def test_parse_request_truncated():
    req = codec.build_read_request("D", 0, 1)[:-2]
    r = codec.parse_request(req)
    assert not r.valid
    assert any("truncated" in e for e in r.errors)


def test_parse_response_too_short_for_end_code():
    # 11B 头 (data_len=0) 后只跟 1 字节: 不足 2B 结束代码
    frame = codec.SUBHEADER_BYTES + b"\x00" * 7 + struct.pack("<H", 0) + b"\x00"
    r = codec.parse_response(frame)
    assert not r.valid
    assert any("too short" in e for e in r.errors)


# ---------------------------------------------------------------- validate


def test_validate_response_all_pass():
    checks = codec.validate_frame(mc_read_resp(), "resp")
    assert all(c.passed for c in checks)
    names = {c.name for c in checks}
    assert {"frame_header_complete", "subheader_3e_binary", "data_length_consistent", "end_code_known"} <= names


def test_validate_request_command_check():
    req = codec.build_read_request("D", 0, 1)
    checks = codec.validate_frame(req, "req")
    by_name = {c.name: c for c in checks}
    assert by_name["command_supported"].passed


def test_validate_subheader_wrong():
    resp = mc_read_resp()
    bad = b"\x50\x50" + resp[2:]
    checks = codec.validate_frame(bad, "resp")
    by_name = {c.name: c for c in checks}
    assert not by_name["subheader_3e_binary"].passed


def test_validate_data_length_inconsistent():
    resp = mc_read_resp() + b"\x00\x00"
    checks = codec.validate_frame(resp, "resp")
    by_name = {c.name: c for c in checks}
    assert not by_name["data_length_consistent"].passed


# ---------------------------------------------------------------- 方向自动判别


def test_parse_auto_request_and_response():
    assert parse_auto("melsec", codec.build_read_request("D", 0, 1)).direction == "req"
    # 正常响应 (首字 0x0000) 与异常响应 (首字 C04F) 都归为 resp
    assert parse_auto("melsec", mc_read_resp()).direction == "resp"
    assert parse_auto("melsec", mc_read_resp(end_code=0xC04F)).direction == "resp"
