"""Modbus codec 纯函数参数化单测 (T2: ≥30 条, 含异常帧与畸形帧)。

全部为纯函数调用, 不碰网络, CI 毫秒级 (D2)。
"""

from __future__ import annotations

import struct

import pytest

from plctap.protocols.modbus import codec


# ---------------------------------------------------------------- build

READ_REQ_FC3 = bytes.fromhex("123400000006" "01" "03" "0000" "000A")


class TestBuildReadRequest:
    def test_fc3_known_bytes(self):
        assert codec.build_read_request(0x1234, 1, 3, 0, 10) == READ_REQ_FC3

    @pytest.mark.parametrize("fc", [1, 2, 3, 4])
    def test_all_read_fcs_shape(self, fc):
        frame = codec.build_read_request(1, 1, fc, 100, 5)
        assert len(frame) == 12
        assert struct.unpack_from(">HHHBBHH", frame, 0) == (1, 0, 6, 1, fc, 100, 5)

    @pytest.mark.parametrize("fc", [1, 2])
    def test_bit_read_limit_2000(self, fc):
        codec.build_read_request(1, 1, fc, 0, 2000)  # 不抛
        with pytest.raises(ValueError, match="quantity"):
            codec.build_read_request(1, 1, fc, 0, 2001)

    @pytest.mark.parametrize("fc", [3, 4])
    def test_register_read_limit_125(self, fc):
        codec.build_read_request(1, 1, fc, 0, 125)  # 不抛
        with pytest.raises(ValueError, match="quantity"):
            codec.build_read_request(1, 1, fc, 0, 126)

    @pytest.mark.parametrize(
        ("unit", "address", "quantity"),
        [(248, 0, 1), (0xFFFF, 0, 1), (1, 0x10000, 1), (1, -1, 1), (1, 0, 0), (1, 0, -5)],
    )
    def test_out_of_bounds_raise(self, unit, address, quantity):
        with pytest.raises(ValueError):
            codec.build_read_request(1, unit, 3, address, quantity)

    def test_unsupported_fc_raises(self):
        with pytest.raises(ValueError, match="fc must be"):
            codec.build_read_request(1, 1, 15, 0, 1)


class TestBuildWriteSingle:
    def test_fc05_on_wire_ff00(self):
        frame = codec.build_write_single(7, 2, 5, 33, 1)
        assert frame == bytes.fromhex("0007000000060205 0021 FF00".replace(" ", ""))

    def test_fc05_off_wire_0000(self):
        frame = codec.build_write_single(7, 2, 5, 33, 0)
        assert frame[10:12] == b"\x00\x00"

    @pytest.mark.parametrize("value", [2, 255, -1])
    def test_fc05_bad_value_raises(self, value):
        with pytest.raises(ValueError, match="coil"):
            codec.build_write_single(1, 1, 5, 0, value)

    def test_fc06_roundtrip(self):
        frame = codec.build_write_single(1, 1, 6, 100, 0xABCD)
        assert frame == bytes.fromhex("000100000006" "01" "06" "0064" "ABCD")


# ---------------------------------------------------------------- parse_request


class TestParseRequest:
    def test_valid_fc3(self):
        r = codec.parse_request(READ_REQ_FC3)
        assert r.valid and not r.errors
        values = {f.name: f.value for f in r.fields}
        assert values["transaction_id"] == 0x1234
        assert values["function_code"] == 3
        assert values["address"] == 0
        assert values["quantity"] == 10

    def test_field_evidence_offsets(self):
        r = codec.parse_request(READ_REQ_FC3)
        by_name = {f.name: f for f in r.fields}
        assert by_name["transaction_id"].byte_offset == 0
        assert by_name["transaction_id"].raw_hex == "1234"
        assert by_name["quantity"].byte_offset == 10
        assert by_name["quantity"].raw_hex == "000a"

    def test_truncated_body(self):
        r = codec.parse_request(READ_REQ_FC3[:10])
        assert not r.valid
        assert any("truncated" in e for e in r.errors)

    def test_too_short_for_mbap(self):
        r = codec.parse_request(b"\x00\x01\x00")
        assert not r.valid
        assert any("MBAP" in e for e in r.errors)

    def test_bad_protocol_id(self):
        frame = bytes.fromhex("0001" "0001" "0006" "01" "03" "0000" "0001")
        r = codec.parse_request(frame)
        assert not r.valid
        assert any("protocol_id" in e for e in r.errors)

    def test_length_field_mismatch(self):
        frame = bytes.fromhex("0001" "0000" "0099" "01" "03" "0000" "0001")
        r = codec.parse_request(frame)
        assert not r.valid
        assert any("length field" in e for e in r.errors)

    def test_unknown_function_code(self):
        frame = bytes.fromhex("0001" "0000" "0006" "01" "47" "0000" "0001")
        r = codec.parse_request(frame)
        assert not r.valid
        assert any("unknown function code" in e for e in r.errors)

    def test_fc05_nonstandard_wire_value(self):
        frame = bytes.fromhex("0001" "0000" "0006" "01" "05" "0000" "1234")
        r = codec.parse_request(frame)
        assert not r.valid
        assert any("0x0000, 0xFF00" in e for e in r.errors)


# ---------------------------------------------------------------- parse_response


def read_resp(tid=1, unit=1, fc=3, values=(0x0102, 0x0304)) -> bytes:
    data = b"".join(v.to_bytes(2, "big") for v in values)
    pdu = struct.pack(">BB", fc, len(data)) + data
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def exception_resp(code=0x02, base_fc=3, tid=1, unit=1, extra=b"") -> bytes:
    return struct.pack(">HHHB", tid, 0, 3, unit) + bytes([base_fc | 0x80, code]) + extra


class TestParseResponse:
    def test_valid_read_response(self):
        r = codec.parse_response(read_resp())
        assert r.valid and not r.errors
        values = {f.name: f.value for f in r.fields}
        assert values["register_values"] == [0x0102, 0x0304]
        assert values["byte_count"] == 4

    def test_field_evidence_offsets(self):
        r = codec.parse_response(read_resp())
        by_name = {f.name: f for f in r.fields}
        assert by_name["register_values"].byte_offset == 9
        assert by_name["register_values"].raw_hex == "01020304"

    def test_exception_response(self):
        r = codec.parse_response(exception_resp(0x02))
        assert r.valid and not r.errors
        by_name = {f.name: f for f in r.fields}
        assert by_name["exception_code"].value == 2
        assert "ILLEGAL_DATA_ADDRESS" in by_name["exception_code"].note

    def test_exception_unknown_code_still_parses(self):
        r = codec.parse_response(exception_resp(0x99))
        assert r.valid  # 未知异常码结构上合法
        assert any("UNKNOWN_0x99" in f.note for f in r.fields if f.name == "exception_code")

    def test_exception_with_trailing_junk(self):
        r = codec.parse_response(exception_resp(0x02, extra=b"\xde\xad"))
        assert not r.valid
        assert any("9 bytes" in e for e in r.errors)

    def test_unknown_function_code(self):
        frame = struct.pack(">HHHB", 1, 0, 3, 1) + bytes([0x47, 0x02])
        r = codec.parse_response(frame)
        assert not r.valid
        assert any("unknown function code" in e for e in r.errors)

    def test_length_field_mismatch(self):
        frame = read_resp()
        frame = frame[:4] + b"\x00\x63" + frame[6:]
        r = codec.parse_response(frame)
        assert not r.valid
        assert any("length field" in e for e in r.errors)

    def test_data_truncated(self):
        frame = read_resp(values=(0x0102, 0x0304))[:-2]  # 声称 4 数据字节实际 2
        r = codec.parse_response(frame)
        assert not r.valid
        assert any("truncated" in e for e in r.errors)

    def test_odd_byte_count_for_registers(self):
        data = b"\x01\x02\x03"
        pdu = struct.pack(">BB", 3, len(data)) + data
        frame = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu
        r = codec.parse_response(frame)
        assert not r.valid
        assert any("odd byte_count" in e for e in r.errors)

    def test_fc05_echo(self):
        req = codec.build_write_single(9, 1, 5, 10, 1)
        r = codec.parse_response(req)  # 回显帧
        assert r.valid
        by_name = {f.name: f.value for f in r.fields}
        assert by_name["address"] == 10
        assert by_name["value"] == 0xFF00

    def test_too_short(self):
        r = codec.parse_response(b"\x00\x01")
        assert not r.valid
        assert any("MBAP" in e for e in r.errors)


class TestCrossCheck:
    def test_tid_mismatch(self):
        req = codec.build_read_request(1, 1, 3, 0, 2)
        resp = read_resp(tid=2, values=(0, 0))
        r = codec.parse_response(resp, request=req)
        assert not r.valid
        assert any("transaction_id mismatch" in e for e in r.errors)

    def test_unit_mismatch(self):
        req = codec.build_read_request(1, 1, 3, 0, 2)
        resp = read_resp(unit=5, values=(0, 0))
        r = codec.parse_response(resp, request=req)
        assert any("unit_id mismatch" in e for e in r.errors)

    def test_fc_mismatch(self):
        req = codec.build_read_request(1, 1, 4, 0, 2)
        resp = read_resp(fc=3, values=(0, 0))
        r = codec.parse_response(resp, request=req)
        assert any("function_code mismatch" in e for e in r.errors)

    def test_exception_fc_base_mismatch(self):
        req = codec.build_read_request(1, 1, 3, 0, 2)
        resp = exception_resp(0x02, base_fc=4)
        r = codec.parse_response(resp, request=req)
        assert any("exception response for fc4" in e for e in r.errors)

    def test_matching_pair_passes(self):
        req = codec.build_read_request(1, 1, 3, 0, 2)
        resp = read_resp(values=(0x11, 0x22))
        r = codec.parse_response(resp, request=req)
        assert r.valid and not r.errors


# ---------------------------------------------------------------- validate


class TestValidateFrame:
    def _all_pass(self, checks):
        return [c for c in checks if not c.passed]

    def test_valid_response_all_pass(self):
        checks = codec.validate_frame(read_resp(), "resp")
        assert checks and not self._all_pass(checks)

    def test_valid_request_all_pass(self):
        checks = codec.validate_frame(READ_REQ_FC3, "req")
        assert checks and not self._all_pass(checks)

    def test_too_short_short_circuits(self):
        checks = codec.validate_frame(b"\x00\x01\x00", "resp")
        assert not checks[0].passed
        assert len(checks) == 1

    def test_missing_function_code(self):
        checks = codec.validate_frame(b"\x00\x01\x00\x00\x00\x00\x01", "resp")
        assert any(c.name == "function_code_known" and not c.passed for c in checks)

    def test_bad_length_field(self):
        frame = read_resp()[:4] + b"\x00\x09" + read_resp()[6:]
        checks = codec.validate_frame(frame, "resp")
        assert any(c.name == "length_field_consistent" and not c.passed for c in checks)

    def test_bad_protocol_id(self):
        frame = b"\x00\x01\x00\x01\x00\x06\x01\x03\x00\x00\x00\x01"
        checks = codec.validate_frame(frame, "resp")
        assert any(c.name == "protocol_id_zero" and not c.passed for c in checks)

    def test_unit_out_of_range(self):
        frame = read_resp(unit=250)
        checks = codec.validate_frame(frame, "resp")
        assert any(c.name == "unit_id_in_range" and not c.passed for c in checks)

    def test_unknown_fc(self):
        frame = struct.pack(">HHHB", 1, 0, 3, 1) + bytes([0x47, 0x00])
        checks = codec.validate_frame(frame, "resp")
        assert any(c.name == "function_code_known" and not c.passed for c in checks)

    def test_response_byte_count_mismatch(self):
        frame = read_resp(values=(1, 2))[:-1]  # 数据少 1 字节
        checks = codec.validate_frame(frame, "resp")
        assert any(c.name == "response_pdu_valid" and not c.passed for c in checks)

    def test_request_quantity_zero(self):
        frame = codec.build_read_request(1, 1, 3, 0, 1)
        frame = frame[:10] + b"\x00\x00"
        checks = codec.validate_frame(frame, "req")
        assert any(c.name == "request_pdu_valid" and not c.passed for c in checks)

    def test_request_quantity_over_limit(self):
        frame = codec.build_read_request(1, 1, 3, 0, 1)
        frame = frame[:10] + struct.pack(">H", 1000)
        checks = codec.validate_frame(frame, "req")
        assert any(c.name == "request_pdu_valid" and not c.passed for c in checks)

    def test_request_address_span_overflow(self):
        # address=0xFFFF, quantity=2 -> 跨 0x10000 上边界
        frame = codec.build_read_request(1, 1, 3, 0xFFFF, 2)
        checks = codec.validate_frame(frame, "req")
        assert any(c.name == "request_pdu_valid" and not c.passed for c in checks)

    def test_request_wrong_total_length(self):
        frame = READ_REQ_FC3[:11]  # 11 字节
        checks = codec.validate_frame(frame, "req")
        assert any(c.name == "request_pdu_valid" and not c.passed for c in checks)

    def test_fc05_bad_wire_value(self):
        frame = codec.build_write_single(1, 1, 5, 0, 1)
        frame = frame[:10] + b"\x00\x01"
        checks = codec.validate_frame(frame, "req")
        assert any(c.name == "request_pdu_valid" and not c.passed for c in checks)

    def test_exception_unknown_code(self):
        checks = codec.validate_frame(exception_resp(0x99), "resp")
        assert any(c.name == "exception_code_known" and not c.passed for c in checks)

    def test_exception_with_extra_bytes(self):
        checks = codec.validate_frame(exception_resp(0x02, extra=b"\x00"), "resp")
        assert any(c.name == "exception_frame_exact_length" and not c.passed for c in checks)


# ---------------------------------------------------------------- 解释


class TestInterpretRegisters:
    def test_uint16_identity(self):
        assert codec.interpret_registers([0xFFFF, 0]) == [65535, 0]

    def test_int16_negative(self):
        assert codec.interpret_registers([0xFFFF], "int16") == [-1]
        assert codec.interpret_registers([0x8000], "int16") == [-32768]
        assert codec.interpret_registers([0x7FFF], "int16") == [32767]

    def test_float32_big_matches_struct(self):
        expected = 123.456
        b = struct.pack(">f", expected)
        regs = [int.from_bytes(b[:2], "big"), int.from_bytes(b[2:], "big")]
        assert codec.interpret_registers(regs, "float32", "big") == [pytest.approx(expected)]

    def test_float32_little_matches_struct(self):
        expected = -0.5
        b = struct.pack("<f", expected)
        regs = [int.from_bytes(b[:2], "little"), int.from_bytes(b[2:], "little")]
        assert codec.interpret_registers(regs, "float32", "little") == [pytest.approx(expected)]

    def test_float32_byteorders_differ(self):
        regs = [0x42F6, 0xE979]
        big = codec.interpret_registers(regs, "float32", "big")
        little = codec.interpret_registers(regs, "float32", "little")
        assert big != little

    def test_float32_odd_count_raises(self):
        with pytest.raises(ValueError, match="even"):
            codec.interpret_registers([1, 2, 3], "float32")

    def test_unknown_datatype_raises(self):
        with pytest.raises(ValueError, match="datatype"):
            codec.interpret_registers([1], "double")

    def test_none_returns_raw(self):
        assert codec.interpret_registers([1, 2], None) == [1, 2]


# ---------------------------------------------------------------- RTU fc16 (回归: parse_rtu fc16 分支曾引用未定义变量)


def _rtu_crc(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def test_parse_rtu_fc16_request():
    body = bytes.fromhex("0110000000020441424344")
    frame = body + struct.pack("<H", _rtu_crc(body))
    r = codec.parse_rtu(frame)
    assert r.valid, r.errors
    by_name = {f.name: f.value for f in r.fields}
    assert by_name["address"] == 0
    assert by_name["quantity"] == 2
    assert by_name["byte_count"] == 4


def test_parse_rtu_fc16_response_auto_direction():
    # fc16 响应恒 8 字节 (回显 start+qty); auto 必须判为响应而非请求
    body = bytes.fromhex("011000000002")
    frame = body + struct.pack("<H", _rtu_crc(body))
    r = codec.parse_rtu(frame)
    assert r.direction == "resp"
    assert r.valid, r.errors
    by_name = {f.name: f.value for f in r.fields}
    assert by_name["address"] == 0
    assert by_name["quantity"] == 2

def test_validate_rtu_fc16_request_shape_ok():
    # 合法 fc16 请求: addr+fc+start2+qty2+bc+data4+crc2 = 13B, 不应被误报 shape
    body = bytes.fromhex("0110000000020441424344")
    frame = body + struct.pack("<H", _rtu_crc(body))
    checks = {c.name: c for c in codec.validate_rtu(frame, "req")}
    assert checks["request_payload_shape"].passed, checks["request_payload_shape"].detail


def test_validate_rtu_fc16_request_byte_count_mismatch_fails():
    # qty=3 但 byte_count=4: 自洽性破坏, 必须报 shape 失败
    body = bytes.fromhex("0110000000030441424344")
    frame = body + struct.pack("<H", _rtu_crc(body))
    checks = {c.name: c for c in codec.validate_rtu(frame, "req")}
    assert not checks["request_payload_shape"].passed, checks["request_payload_shape"].detail


def test_validate_rtu_fc16_auto_direction_request():
    # auto 方向: 13B fc16 必须判为请求, 且全项通过 (回归: auto 曾把 13B 判成响应)
    body = bytes.fromhex("0110000000020441424344")
    frame = body + struct.pack("<H", _rtu_crc(body))
    checks = codec.validate_rtu(frame)  # direction=auto
    failed = [c for c in checks if not c.passed]
    assert not failed, [c.detail for c in failed]
