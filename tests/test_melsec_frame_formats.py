"""MELSEC MC 帧格式扩展测试: 3E ASCII / 4E binary / 4E ASCII。

测试策略: 对每种格式构造请求帧 → 构造对应响应帧 → 用格式化 parser
双向解析 → 校验字段回显、数据值、end_code、data_length 自洽。
"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.melsec import codec
from plctap.protocols.melsec.codec import (
    FRAME_3E_ASCII,
    FRAME_3E_BINARY,
    FRAME_4E_ASCII,
    FRAME_4E_BINARY,
    FRAME_FORMATS,
)

# ---------------------------------------------------------------- helpers


def enc_ascii(value: int, width_bytes: int) -> bytes:
    mask = (1 << (width_bytes * 8)) - 1
    return format(value & mask, f"0{width_bytes * 2}X").encode("ascii")


def build_ascii_header(sub: str, net: int, pc: int, io: int, sta: int, data_len: int, serial: int = 0, is_4e: bool = False) -> bytes:
    """响应帧头 (ASCII): 副头部 + 路由 + 数据长 (响应无定时器)。"""
    out = sub.encode("ascii")
    if is_4e:
        out += enc_ascii(serial, 2) + enc_ascii(0, 2)
    out += enc_ascii(net, 1) + enc_ascii(pc, 1)
    out += enc_ascii(io, 2) + enc_ascii(sta, 1)
    out += enc_ascii(data_len, 2)
    return out


def build_binary_header(sub: int, net: int, pc: int, io: int, sta: int, data_len: int, serial: int = 0, is_4e: bool = False) -> bytes:
    """响应帧头: 副头部 + 路由5B + 数据长2B (响应无定时器)。"""
    out = struct.pack(">H", sub)  # 子头部线上大端
    if is_4e:
        out += struct.pack("<HH", serial, 0)
    out += bytes([net, pc]) + struct.pack("<H", io) + bytes([sta])
    out += struct.pack("<H", data_len)
    return out


def build_resp(fmt: str, words: list[int], end_code: int = 0, net: int = 0, pc: int = 0xFF, serial: int = 0) -> bytes:
    """标准响应: 副头部(D0 00/D4 00) + 路由5B + 数据长2B(=结束码+数据) + 结束码 + 数据。"""
    is_ascii = fmt in (FRAME_3E_ASCII, FRAME_4E_ASCII)
    is_4e = fmt in (FRAME_4E_BINARY, FRAME_4E_ASCII)
    sub = 0xD000 if not is_4e else 0xD400
    sub_str = "D000" if not is_4e else "D400"
    if is_ascii:
        data = enc_ascii(end_code, 2) + b"".join(enc_ascii(w, 2) for w in words)
        header = build_ascii_header(sub_str, net, pc, 0x03FF, 0, len(data), serial=serial, is_4e=is_4e)
    else:
        data = struct.pack("<H", end_code) + b"".join(struct.pack("<H", w) for w in words)
        header = build_binary_header(sub, net, pc, 0x03FF, 0, len(data), serial=serial, is_4e=is_4e)
    return header + data


# ---------------------------------------------------------------- build: 4 formats


class TestBuildReadRequest:
    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    def test_build_all_formats(self, fmt):
        frame = codec.build_read_request("D", 100, 2, frame_format=fmt)
        hl = codec.header_len(fmt)
        assert len(frame) > hl
        sub, net, pc, io, sta, timer, data_len, serial = codec._parse_header_fmt(frame, fmt)
        assert sub == codec._SUBHEADERS[fmt]
        assert data_len == codec._tail_bytes(frame, fmt)

    def test_3e_ascii_layout(self):
        frame = codec.build_read_request("D", 100, 2, frame_format=FRAME_3E_ASCII)
        # header: "5000" + "00" + "FF" + "03FF" + "00" + data_len(4) + timer(4) = 22 chars
        assert frame[0:4] == b"5000"
        assert frame[4:6] == b"00"  # network
        assert frame[6:8] == b"FF"  # pc (default 0xFF)
        assert frame[8:12] == b"03FF"  # module_io
        assert frame[14:18] == b"0018"  # data_len = 24 字符 (timer4 + data20)
        # PDU starts at 22
        pdu = frame[22:]
        assert pdu[0:4] == b"0401"  # command
        assert pdu[4:8] == b"0000"  # subcommand
        assert pdu[8:10] == b"D*"  # device_code (ASCII 2 字符, 在前)
        assert pdu[10:16] == b"000100"  # head_device 100 十进制
        assert pdu[16:20] == b"0002"  # count

    def test_4e_binary_layout(self):
        frame = codec.build_read_request("D", 100, 2, frame_format=FRAME_4E_BINARY, serial=42)
        assert struct.unpack_from(">H", frame, 0)[0] == 0x5400
        assert struct.unpack_from("<H", frame, 2)[0] == 42  # serial
        assert struct.unpack_from("<H", frame, 4)[0] == 0  # reserved
        # PDU starts at 15 (not 11 like 3E)
        pdu = frame[15:]
        assert struct.unpack_from("<H", pdu, 0)[0] == 0x0401

    def test_4e_ascii_layout(self):
        frame = codec.build_read_request("D", 100, 2, frame_format=FRAME_4E_ASCII, serial=42)
        assert frame[0:4] == b"5400"
        assert frame[4:8] == b"002A"  # serial 42 = 0x2A
        assert frame[8:12] == b"0000"  # reserved
        # PDU starts at 30
        pdu = frame[30:]
        assert pdu[0:4] == b"0401"


# ---------------------------------------------------------------- parse: roundtrip


class TestParseRoundtrip:
    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    @pytest.mark.parametrize("words", [[], [0x1234], [0x1234, 0xBEEF], [1, 2, 3, 4, 5]])
    def test_build_parse_response_roundtrip(self, fmt, words):
        resp = build_resp(fmt, words=words)
        r = codec.parse_response_fmt(resp, frame_format=fmt)
        assert r.valid, r.errors
        by_name = {f.name: f for f in r.fields}
        assert by_name["end_code"].value == 0
        assert by_name["word_values"].value == words

    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    def test_build_parse_request_roundtrip(self, fmt):
        req = codec.build_read_request("D", 100, 2, frame_format=fmt)
        r = codec.parse_request_fmt(req, frame_format=fmt)
        assert r.valid, r.errors
        by_name = {f.name: f for f in r.fields}
        assert by_name["device_code"].value == 0xA8
        assert by_name["head_device"].value == 100
        assert by_name["device_count"].value == 2

    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    def test_cross_check_echo(self, fmt):
        req = codec.build_read_request("D", 0, 1, network=3, pc=5, frame_format=fmt)
        # build response with wrong pc (6 instead of 5)
        resp = build_resp(fmt, words=[1], net=3, pc=6)
        r = codec.parse_response_fmt(resp, request=req, frame_format=fmt)
        assert any("pc_number mismatch" in e for e in r.errors)

    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    def test_end_code_nonzero(self, fmt):
        resp = build_resp(fmt, words=[], end_code=0xC04F)
        r = codec.parse_response_fmt(resp, frame_format=fmt)
        by_name = {f.name: f for f in r.fields}
        assert r.valid  # structural validity, not business success
        assert by_name["end_code"].value == 0xC04F
        assert by_name["end_code"].note == "DEVICE_NUMBER_OUT_OF_RANGE"

    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    def test_data_short(self, fmt):
        req = codec.build_read_request("D", 0, 5, frame_format=fmt)
        resp = build_resp(fmt, words=[1, 2])
        r = codec.parse_response_fmt(resp, request=req, frame_format=fmt)
        assert any("data short" in e for e in r.errors)


# ---------------------------------------------------------------- validate


class TestValidate:
    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    def test_validate_response_all_pass(self, fmt):
        resp = build_resp(fmt, words=[1])
        checks = codec.validate_frame_fmt(resp, "resp", frame_format=fmt)
        assert all(c.passed for c in checks), [c.detail for c in checks if not c.passed]

    @pytest.mark.parametrize("fmt", FRAME_FORMATS)
    def test_validate_request(self, fmt):
        req = codec.build_read_request("D", 0, 1, frame_format=fmt)
        checks = codec.validate_frame_fmt(req, "req", frame_format=fmt)
        by_name = {c.name: c for c in checks}
        assert by_name["command_supported"].passed
        assert by_name["subheader_match"].passed

    def test_validate_wrong_subheader_4e(self):
        resp = build_resp(FRAME_4E_BINARY, words=[1])
        # corrupt subheader to 3E value
        bad = struct.pack(">H", 0x5000) + resp[2:]
        checks = codec.validate_frame_fmt(bad, "resp", frame_format=FRAME_4E_BINARY)
        by_name = {c.name: c for c in checks}
        assert not by_name["subheader_match"].passed


# ---------------------------------------------------------------- header length


class TestHeaderLens:
    def test_3e_binary_is_11(self):
        assert codec.header_len(FRAME_3E_BINARY) == 11

    def test_3e_ascii_is_22(self):
        assert codec.header_len(FRAME_3E_ASCII) == 22

    def test_4e_binary_is_15(self):
        assert codec.header_len(FRAME_4E_BINARY) == 15

    def test_4e_ascii_is_30(self):
        assert codec.header_len(FRAME_4E_ASCII) == 30


# ---------------------------------------------------------------- backward compat


class TestBackwardCompat:
    def test_build_read_request_default_is_3e_binary(self):
        """Without frame_format, produce identical frame to explicit 3e_binary."""
        a = codec.build_read_request("D", 100, 2)
        b = codec.build_read_request("D", 100, 2, frame_format=FRAME_3E_BINARY)
        assert a == b

    def test_parse_response_default_is_3e_binary(self):
        resp = build_resp(FRAME_3E_BINARY, words=[1])
        r1 = codec.parse_response(resp)
        r2 = codec.parse_response_fmt(resp, frame_format=FRAME_3E_BINARY)
        assert r1.valid == r2.valid
        assert len(r1.fields) == len(r2.fields)
