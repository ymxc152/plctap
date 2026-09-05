# -*- coding: utf-8 -*-
"""新增测试: 非标 FINS 设备方向检测 + 写命令解析 + 多解释。

用例来自用户实测帧 (IoTServer/网关类设备的非标响应格式),
用于验证修复后 parser 能正确处理。
"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.fins import codec
from plctap.protocols.auto import parse_auto
from plctap.protocols.common import interpret_all, interpret_registers


# ------------------------------------------------------- 用户实测帧 (非标设备)

# 用户设备的读响应: TCP cmd=0x00 (非标, 应为 0x04), FINS 头全零, 数据在尾部
USER_READ_RESP = (
    "46494E530000001A"  # magic + length=26
    "00000000"           # tcp command=0 (非标: 不是 0x04)
    "00000000"           # tcp error=0
    "00000000000000000000"  # FINS header 10B 全零 (非标: 应有 ICF=0xC0 等)
    "0000"               # FINS cmd=0x0000 (非标: 应为 0x0101)
    "0000"               # end_code=0x0000 (normal)
    "0000"               # data word 1 = 0x0000
    "4270"               # data word 2 = 0x4270 (= 17008 uint16)
).replace(" ", "")

# 用户设备的写响应: TCP cmd=0x00, FINS 全零, 无数据 (写响应)
USER_WRITE_RESP = (
    "46494E5300000016"  # magic + length=22
    "00000000"           # tcp command=0
    "00000000"           # tcp error=0
    "00000000000000000000"  # FINS header 10B 全零
    "0000"               # FINS cmd=0x0000
    "0000"               # end_code=0x0000
).replace(" ", "")


class TestNonStandardFinsDirection:
    """非标设备 (IoTServer/网关) 的 FINS/TCP 帧方向自动判别。"""

    def test_cmd0_long_payload_is_response_not_handshake(self):
        """cmd=0x00 + payload>=14B 应判为 FINS 响应 (非标设备), 而非握手请求。"""
        frame = bytes.fromhex(USER_READ_RESP)
        r = parse_auto("fins", frame)
        assert r.direction == "resp", (
            f"expected direction='resp' for non-standard FINS response, got '{r.direction}'; "
            f"errors={r.errors}"
        )

    def test_cmd0_short_payload_is_handshake_request(self):
        """cmd=0x00 + payload=4B 应判为握手请求 (标准行为不变)。"""
        frame = codec.build_handshake_request(1)
        r = parse_auto("fins", frame)
        assert r.direction == "req"

    def test_nonstandard_read_resp_data_words(self):
        """非标读响应应能正确提取数据字 (含 0x4270)。"""
        frame = bytes.fromhex(USER_READ_RESP)
        r = parse_auto("fins", frame)
        assert r.valid, f"expected valid, errors={r.errors}"
        by_name = {f.name: f for f in r.fields}
        assert "word_values" in by_name
        values = by_name["word_values"].value
        assert 0x4270 in values, f"expected 0x4270 in {values}"

    def test_nonstandard_write_resp_no_data(self):
        """非标写响应 (FINS 全零, 无数据) 应 valid=True 且 end_code=0。"""
        frame = bytes.fromhex(USER_WRITE_RESP)
        r = parse_auto("fins", frame)
        assert r.direction == "resp"
        assert r.valid, f"expected valid, errors={r.errors}"
        by_name = {f.name: f for f in r.fields}
        assert by_name["end_code"].value == 0

    def test_standard_exchange_cmd04_still_works(self):
        """标准 Omron 设备 (cmd=0x04, ICF=0xC0) 方向判别不应被破坏。"""
        frame = codec.build_tcp_frame(
            codec.TCP_CMD_EXCHANGE,
            bytes([0xC0, 0x00, 0x02])
            + bytes([0x00, 0x01, 0x00])
            + bytes([0x00, 0x01, 0x00])
            + bytes([0x01])
            + struct.pack(">H", 0x0101)
            + struct.pack(">H", 0x0000)
            + struct.pack(">H", 0x1234),
        )
        r = parse_auto("fins", frame)
        assert r.direction == "resp"


class TestFinsWriteCommandParsing:
    """FINS 写命令 (0x0102) 请求帧解析。"""

    def test_parse_write_request(self):
        """0102 写请求应解析出 area/address/count/write_data。"""
        fins = (
            bytes([0x80, 0x00, 0x02])  # ICF=0x80, RSV, GCT
            + bytes([0x00, 0x01, 0x00])  # DNA DA1 DA2
            + bytes([0x00, 0x0B, 0x00])  # SNA SA1 SA2
            + bytes([0x00])  # SID
            + struct.pack(">H", codec.CMD_MEMORY_AREA_WRITE)  # 0102
            + bytes([0x82])  # DM area
            + struct.pack(">H", 91)  # address=91
            + bytes([0x00])  # bit=0
            + struct.pack(">H", 2)  # count=2
            + struct.pack(">H", 0x0000)  # data word 1
            + struct.pack(">H", 0x4270)  # data word 2
        )
        frame = codec.build_tcp_frame(codec.TCP_CMD_EXCHANGE, fins)
        r = codec.parse_request(frame)
        assert r.valid, f"errors={r.errors}"
        by_name = {f.name: f for f in r.fields}
        assert by_name["command_code"].value == codec.CMD_MEMORY_AREA_WRITE
        assert by_name["area_code"].value == 0x82
        assert by_name["address"].value == 91
        assert by_name["count"].value == 2
        assert "write_data" in by_name
        assert by_name["write_data"].value == [0x0000, 0x4270]

    def test_parse_read_request_still_works(self):
        """0101 读请求解析不应被改动破坏。"""
        req = codec.build_read_request(1, 1, 0x82, 42, 2)
        r = codec.parse_request(req)
        assert r.valid
        by_name = {f.name: f for f in r.fields}
        assert by_name["command_code"].value == codec.CMD_MEMORY_AREA_READ


class TestICFDirectionNotes:
    """ICF 字段的 note 应标明 bit6=响应标志 (而非 bit7)。"""

    def test_icf_note_mentions_bit6(self):
        req = codec.build_read_request(1, 1, 0x82, 0, 1)
        r = codec.parse_request(req)
        icf_field = next(f for f in r.fields if f.name == "icf")
        assert "bit6" in icf_field.note


# ------------------------------------------------------- 多解释 (interpret_all)


class TestInterpretAll:
    """datatype=None 时返回所有常见数据类型解释。"""

    def test_float32_little_detected(self):
        """用户实测: DM91-92 存 float32 小端 60.0, 原始值 [0, 0x4270]。"""
        result = interpret_all([0, 0x4270])
        assert "float32_little" in result
        assert result["float32_little"] == [pytest.approx(60.0)]

    def test_uint16_preserved(self):
        result = interpret_all([1234, 5678])
        assert result["uint16"] == [1234, 5678]

    def test_int16_negative(self):
        result = interpret_all([0xFFFF])
        assert result["int16"] == [-1]

    def test_int32_combinations(self):
        result = interpret_all([0x0064, 0x01F4])
        assert result["int32_big"] == [0x006401F4]
        assert result["int32_little"] == [0x01F40064]

    def test_float32_big(self):
        # 1.0 = 0x3F800000: big = [0x3F80, 0x0000]
        result = interpret_all([0x3F80, 0x0000])
        assert result["float32_big"] == [pytest.approx(1.0)]

    def test_single_register_no_32bit(self):
        """单个寄存器不产生 32 位解释。"""
        result = interpret_all([42])
        assert "float32_big" not in result
        assert "int32_big" not in result

    def test_three_registers_no_32bit(self):
        """奇数个寄存器不产生 32 位解释。"""
        result = interpret_all([1, 2, 3])
        assert "float32_big" not in result


class TestInterpretRegistersFloat32Little:
    """验证 interpret_registers 支持小端 float32 (与用户设备一致)。"""

    def test_60_float32_little(self):
        # 60.0 = 0x42700000 → 高字 0x4270, 低字 0x0000
        # little: 低字在前 → [0x0000, 0x4270]
        result = interpret_registers([0x0000, 0x4270], "float32", "little")
        assert result == [pytest.approx(60.0)]
