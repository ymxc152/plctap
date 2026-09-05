"""流分帧纯函数测试 (M3: streams.py, listener/parse_pcap 共用)。"""

from __future__ import annotations

import pytest

from plctap import streams
from plctap.protocols.fins import codec as fins_codec
from plctap.protocols.melsec import codec as mc_codec
from plctap.protocols.modbus.codec import build_read_request


def _split(protocol, data: bytes):
    return streams.split_frames(protocol, data)


# ---------------------------------------------------------------- modbus


def test_modbus_single_frame():
    frame = build_read_request(1, 1, 3, 0, 2)
    frames, tail = _split("modbus", frame)
    assert frames == [frame] and tail == b""


def test_modbus_partial_then_complete():
    frame = build_read_request(1, 1, 3, 0, 2)
    assert streams.try_frame_len("modbus", frame[:6]) is None  # 只够头部
    assert streams.try_frame_len("modbus", frame) == len(frame)


def test_modbus_two_frames_and_partial_tail():
    a = build_read_request(1, 1, 3, 0, 2)
    b = build_read_request(2, 1, 3, 0, 2)
    frames, tail = _split("modbus", a + b + a[:4])
    assert frames == [a, b]
    assert tail == a[:4]


def test_modbus_bad_length_is_broken_stream():
    # 长度字段 = 0xFF00 -> 帧长超护栏, try_frame_len 返回 0
    bad = bytes.fromhex("0001000000ff00" + "01" + "03")
    assert streams.try_frame_len("modbus", bad) == 0
    frames, tail = _split("modbus", bad)
    assert frames == [] and tail == bad


# ---------------------------------------------------------------- fins


def test_fins_single_frame():
    frame = fins_codec.build_read_request(1, 1, fins_codec.AREA_CODES["DM"], 0, 2)
    frames, tail = _split("fins", frame)
    assert frames == [frame] and tail == b""


def test_fins_length_field_is_8_plus_payload():
    # build_read_request: length = 8 + payload; 帧长 = 8 + length 字段
    frame = fins_codec.build_handshake_request(1)
    (length,) = __import__("struct").unpack_from(">I", frame, 4)
    assert streams.try_frame_len("fins", frame) == 8 + length


def test_fins_bad_magic_still_frames():
    # 分帧只看长度字段, 不验 magic (magic 校验属于 parse/validate)
    frame = fins_codec.build_handshake_request(1)
    bad = b"XXXX" + frame[4:]
    assert streams.try_frame_len("fins", bad) == len(frame)


# ---------------------------------------------------------------- melsec


def test_melsec_single_frame():
    frame = mc_codec.build_read_request("D", 0, 2)
    frames, tail = _split("melsec", frame)
    assert frames == [frame] and tail == b""


def test_melsec_partial():
    frame = mc_codec.build_read_request("D", 0, 2)
    assert streams.try_frame_len("melsec", frame[:9]) is None
    assert streams.try_frame_len("melsec", frame) == len(frame)


@pytest.mark.parametrize("protocol", ["modbus", "fins", "melsec"])
def test_empty_input(protocol):
    frames, tail = _split(protocol, b"")
    assert frames == [] and tail == b""
