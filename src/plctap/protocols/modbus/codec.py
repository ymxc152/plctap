"""Modbus TCP 帧编解码纯函数 (HANDOFF T2)。

依据: MODBUS Application Protocol Specification V1.1b3 (modbus.org)。
- Modbus TCP **无 CRC** (RTU 才有); TCP 侧完整性校验以 MBAP 长度一致性为主。
- 全部函数不碰 socket (D2): 单测毫秒级, 评测 harness 与 ProtoForge 故障
  注入直接调用本模块。
- 每个解析字段带 byte_offset 与 raw_hex, 供 diagnose 引用证据 (D2)。
- 行为对齐参考 pymodbus, 但解析为纯手写 (BUILD.md 第 3 节)。
"""

from __future__ import annotations

import struct
from typing import Literal

from plctap.models import CheckResult, FrameField, ParseResult

# 功能码 (M1 覆盖读 1-4 与单写 5-6; 多写 15/16 留 M3 写闸门)
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_REGISTERS = 16

READ_FCS = (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS)
WRITE_FCS = (WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER)
KNOWN_FCS = READ_FCS + WRITE_FCS + (WRITE_MULTIPLE_REGISTERS,)

EXCEPTION_FLAG = 0x80  # 异常响应功能码 = 请求 FC | 0x80

MBAP_LEN = 7  # 事务号2 + 协议号2 + 长度2 + 单元号1
PROTOCOL_ID = 0
MAX_READ_BITS = 2000  # fc01/02 单次最大读点数
MAX_READ_REGS = 125   # fc03/04 单次最大读寄存器数
MAX_UNIT_ID = 247     # 248-255 保留, 0 为广播 (RTU 语义)

EXCEPTION_CODES: dict[int, str] = {
    0x01: "ILLEGAL_FUNCTION",
    0x02: "ILLEGAL_DATA_ADDRESS",
    0x03: "ILLEGAL_DATA_VALUE",
    0x04: "SERVER_DEVICE_FAILURE",
    0x05: "ACKNOWLEDGE",
    0x06: "SERVER_DEVICE_BUSY",
    0x08: "MEMORY_PARITY_ERROR",
    0x0A: "GATEWAY_PATH_UNAVAILABLE",
    0x0B: "GATEWAY_TARGET_FAILED_TO_RESPOND",
}


def exception_name(code: int) -> str:
    return EXCEPTION_CODES.get(code, f"UNKNOWN_{code:#04x}")


def read_limit(fc: int) -> int:
    """fc01/02 位读取上限 2000, fc03/04 寄存器上限 125 (规范 6.x 节)。"""
    return MAX_READ_BITS if fc in (READ_COILS, READ_DISCRETE_INPUTS) else MAX_READ_REGS


# ---------------------------------------------------------------- build


def build_read_request(
    transaction_id: int, unit: int, function_code: int, address: int, quantity: int
) -> bytes:
    """构造 fc01-04 读请求帧 (MBAP 7B + PDU 5B)。

    参数不合法直接抛 ValueError —— build 层保证"合法输入才有合法帧",
    让调用方(工具层/测试)在发出前就拿到明确错误。
    """
    if function_code not in READ_FCS:
        raise ValueError(f"build_read_request: fc must be one of {READ_FCS}, got {function_code}")
    if not 0 <= unit <= MAX_UNIT_ID:
        raise ValueError(f"unit id {unit} out of range 0-{MAX_UNIT_ID}")
    if not 0 <= address <= 0xFFFF:
        raise ValueError(f"address {address} out of range 0-65535")
    if not 1 <= quantity <= read_limit(function_code):
        raise ValueError(
            f"quantity {quantity} out of range 1-{read_limit(function_code)} for fc{function_code}"
        )
    pdu = struct.pack(">BHH", function_code, address, quantity)
    return _mbap(transaction_id, unit, len(pdu)) + pdu


def build_write_single(
    transaction_id: int, unit: int, function_code: int, address: int, value: int
) -> bytes:
    """构造 fc05 (写单线圈) / fc06 (写单寄存器) 请求帧 (M3 写闸门用)。

    fc05 的应用值只有 0/1, 线上分别为 0x0000 / 0xFF00 (规范 6.5 节),
    这里在 build 层做转换与校验, 拒绝其它值。
    """
    if function_code not in WRITE_FCS:
        raise ValueError(f"build_write_single: fc must be one of {WRITE_FCS}, got {function_code}")
    if not 0 <= unit <= MAX_UNIT_ID:
        raise ValueError(f"unit id {unit} out of range 0-{MAX_UNIT_ID}")
    if not 0 <= address <= 0xFFFF:
        raise ValueError(f"address {address} out of range 0-65535")
    if function_code == WRITE_SINGLE_COIL:
        if value not in (0, 1):
            raise ValueError("fc05 coil value must be 0 or 1")
        wire_value = 0xFF00 if value else 0x0000
    else:
        if not 0 <= value <= 0xFFFF:
            raise ValueError(f"register value {value} out of range 0-65535")
        wire_value = value
    pdu = struct.pack(">BHH", function_code, address, wire_value)
    return _mbap(transaction_id, unit, len(pdu)) + pdu



def build_write_multiple(tid: int, unit: int, address: int, values: list[int]) -> bytes:
    """fc16 写多个寄存器。values 为 16 位无符号整数列表。"""
    if not values:
        raise ValueError("values must not be empty")
    if not 1 <= len(values) <= 123:
        raise ValueError(f"fc16 supports 1-123 registers, got {len(values)}")
    for v in values:
        if not 0 <= v <= 0xFFFF:
            raise ValueError(f"register value {v} out of range 0-65535")
    byte_count = len(values) * 2
    data = b"".join(struct.pack(">H", v) for v in values)
    pdu = (
        struct.pack(">BHHB", WRITE_MULTIPLE_REGISTERS, address, len(values), byte_count)
        + data
    )
    mbap = struct.pack(">HHHB", tid, PROTOCOL_ID, 1 + len(pdu), unit)
    return mbap + pdu


def _mbap(transaction_id: int, unit: int, pdu_len: int) -> bytes:
    """MBAP 头: 长度字段 = unit(1) + PDU 字节数, 即其后所有字节的长度。"""
    return struct.pack(">HHHB", transaction_id, PROTOCOL_ID, pdu_len + 1, unit)


# ---------------------------------------------------------------- parse


def _field(frame: bytes, name: str, value: object, offset: int, size: int, note: str = "") -> FrameField:
    """构造带证据的字段: byte_offset 为全帧偏移, raw_hex 为原始片段。"""
    return FrameField(
        name=name,
        value=value,
        raw_hex=frame[offset : offset + size].hex(),
        byte_offset=offset,
        note=note,
    )


def parse_request(frame: bytes) -> ParseResult:
    """解析请求帧 (fc01-06)。畸形帧不抛异常, 尽量解析并记入 errors ——
    诊断场景里"解析失败的方式"本身就是证据。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    if len(frame) < MBAP_LEN:
        return ParseResult(
            protocol="modbus",
            direction="req",
            fields=fields,
            valid=False,
            errors=[f"frame too short for MBAP header: {len(frame)} < {MBAP_LEN} bytes"],
        )
    tid, pid, length = struct.unpack_from(">HHH", frame, 0)
    unit = frame[6]
    fields.append(_field(frame, "transaction_id", tid, 0, 2))
    fields.append(_field(frame, "protocol_id", pid, 2, 2, "Modbus TCP 固定 0"))
    fields.append(_field(frame, "length", length, 4, 2, "unit + PDU 字节数"))
    fields.append(_field(frame, "unit_id", unit, 6, 1))

    if pid != PROTOCOL_ID:
        errors.append(f"protocol_id must be 0, got {pid}")
    if length != len(frame) - 6:
        errors.append(f"length field {length} != actual bytes after length field ({len(frame) - 6})")
    if len(frame) < 8:
        errors.append("frame truncated: missing function code")
        return ParseResult(protocol="modbus", direction="req", fields=fields, valid=False, errors=errors)

    fc = frame[7]
    fields.append(_field(frame, "function_code", fc, 7, 1))
    if fc not in KNOWN_FCS:
        errors.append(f"unknown function code {fc:#04x} in request")
        return ParseResult(protocol="modbus", direction="req", fields=fields, valid=False, errors=errors)

    if len(frame) < 12:
        errors.append(f"frame truncated: request PDU needs 4 more bytes, have {len(frame) - 8}")
        return ParseResult(protocol="modbus", direction="req", fields=fields, valid=False, errors=errors)

    address, operand = struct.unpack_from(">HH", frame, 8)
    if fc in READ_FCS:
        fields.append(_field(frame, "address", address, 8, 2))
        note = f"quantity bounds: 1-{read_limit(fc)} for fc{fc}"
        fields.append(_field(frame, "quantity", operand, 10, 2, note))
        if not 1 <= operand <= read_limit(fc):
            errors.append(f"quantity {operand} out of range 1-{read_limit(fc)} for fc{fc}")
    else:
        fields.append(_field(frame, "address", address, 8, 2))
        if fc == WRITE_SINGLE_COIL:
            value = 1 if operand == 0xFF00 else 0 if operand == 0x0000 else operand
            note = "" if operand in (0x0000, 0xFF00) else "non-standard coil value (must be 0x0000/0xFF00)"
            if note:
                errors.append(f"fc05 coil wire value {operand:#06x} not in {{0x0000, 0xFF00}}")
            fields.append(_field(frame, "value", value, 10, 2, note))
        else:
            fields.append(_field(frame, "value", operand, 10, 2))
    if not 0 <= unit <= MAX_UNIT_ID:
        errors.append(f"unit id {unit} out of range 0-{MAX_UNIT_ID}")
    return ParseResult(protocol="modbus", direction="req", fields=fields, valid=not errors, errors=errors)


def parse_response(frame: bytes, request: bytes | None = None) -> ParseResult:
    """解析响应帧 (正常读响应 / fc05-06 回显 / 异常响应)。

    request 提供时做交叉校验: 事务号/单元号/功能码回显一致、
    数据字节数与请求 quantity 匹配 —— 事务号乱序、长度不符这类
    故障 (BUILD.md 第 4 节注入清单) 就在这一层被捕获。
    """
    errors: list[str] = []
    fields: list[FrameField] = []
    if len(frame) < MBAP_LEN:
        return ParseResult(
            protocol="modbus",
            direction="resp",
            fields=fields,
            valid=False,
            errors=[f"frame too short for MBAP header: {len(frame)} < {MBAP_LEN} bytes"],
        )
    tid, pid, length = struct.unpack_from(">HHH", frame, 0)
    unit = frame[6]
    fields.append(_field(frame, "transaction_id", tid, 0, 2))
    fields.append(_field(frame, "protocol_id", pid, 2, 2))
    fields.append(_field(frame, "length", length, 4, 2))
    fields.append(_field(frame, "unit_id", unit, 6, 1))

    if pid != PROTOCOL_ID:
        errors.append(f"protocol_id must be 0, got {pid}")
    if length != len(frame) - 6:
        errors.append(f"length field {length} != actual bytes after length field ({len(frame) - 6})")

    if request is not None:
        errors.extend(_cross_check(frame, request))

    if len(frame) < 8:
        errors.append("frame truncated: missing function code")
        return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=False, errors=errors)

    fc = frame[7]
    if fc & EXCEPTION_FLAG:
        base_fc = fc & 0x7F
        fields.append(
            _field(frame, "function_code", fc, 7, 1, f"exception response for fc{base_fc}")
        )
        if base_fc not in KNOWN_FCS:
            errors.append(f"unknown base function code {base_fc:#04x} in exception response")
        if len(frame) < 9:
            errors.append("frame truncated: missing exception code")
            return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=False, errors=errors)
        code = frame[8]
        fields.append(
            _field(frame, "exception_code", code, 8, 1, exception_name(code))
        )
        if len(frame) != 9:
            errors.append(f"exception response should be 9 bytes, got {len(frame)}")
        return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=not errors, errors=errors)

    fields.append(_field(frame, "function_code", fc, 7, 1))
    if fc not in KNOWN_FCS:
        errors.append(f"unknown function code {fc:#04x} in response")
        return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=False, errors=errors)

    if fc in READ_FCS:
        if len(frame) < 9:
            errors.append("frame truncated: missing byte count")
            return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=False, errors=errors)
        byte_count = frame[8]
        fields.append(_field(frame, "byte_count", byte_count, 8, 1))
        data = frame[9:]
        if len(data) < byte_count:
            errors.append(f"data truncated: byte_count {byte_count}, actual {len(data)}")
            byte_count = len(data)
        if byte_count % 2 != 0 and fc in (READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
            errors.append(f"odd byte_count {byte_count} for 16-bit register read fc{fc}")
        values = [
            int.from_bytes(data[i : i + 2], "big")  # 寄存器内容按规范恒为大端
            for i in range(0, byte_count - 1, 2)
        ]
        fields.append(
            _field(frame, "register_values", values, 9, byte_count,
                   "16-bit big-endian register values")
        )
    else:
        # fc05/06 响应为请求回显
        if len(frame) < 12:
            errors.append(f"frame truncated: fc{fc} response needs 12 bytes, have {len(frame)}")
            return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=False, errors=errors)
        address, operand = struct.unpack_from(">HH", frame, 8)
        fields.append(_field(frame, "address", address, 8, 2))
        fields.append(_field(frame, "value", operand, 10, 2))

    return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=not errors, errors=errors)


def _cross_check(frame: bytes, request: bytes) -> list[str]:
    """响应与请求的配对校验 (事务号回显、单元号一致、功能码对应、读响应字节数与 quantity 匹配)。

    字节数校验是回显/串包甄别的关键: 网关/调试工具把请求原样弹回时,
    tid/unit/fc 全部"匹配", 只有 byte_count != 2*quantity 能识破。
    """
    problems: list[str] = []
    if len(request) < 8:
        return ["request too short to cross-check"]
    r_tid, r_pid, r_len = struct.unpack_from(">HHH", request, 0)
    r_unit = request[6]
    r_fc = request[7]
    tid, _pid, _length = struct.unpack_from(">HHH", frame, 0)
    if len(frame) < 8:
        return problems
    fc = frame[7]
    if tid != r_tid:
        problems.append(f"transaction_id mismatch: request {r_tid}, response {tid}")
    if len(frame) > 6 and frame[6] != r_unit:
        problems.append(f"unit_id mismatch: request {r_unit}, response {frame[6]}")
    if fc & EXCEPTION_FLAG:
        if (fc & 0x7F) != r_fc:
            problems.append(f"exception response for fc{fc & 0x7F}, but request fc was {r_fc}")
    elif fc != r_fc:
        problems.append(f"function_code mismatch: request fc{r_fc}, response fc{fc}")
    elif r_fc in (READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS) and len(frame) >= 9:
        qty = struct.unpack_from(">H", request, 10)[0] if len(request) >= 12 else 0
        byte_count = frame[8]
        if byte_count != qty * 2:
            problems.append(
                f"byte_count {byte_count} != 2 * quantity {qty} from request"
            )
    return problems


# ---------------------------------------------------------------- validate


def validate_frame(
    frame: bytes, direction: Literal["req", "resp"] = "resp"
) -> list[CheckResult]:
    """校验清单逐项 pass/fail (PLAN.md 诊断层: 长度/功能码/地址边界)。

    与 parse 的区别: parse 关注"每段字节是什么", validate 关注
    "这一帧是否符合规范", 输出固定的检查项列表便于逐项展示。
    """
    checks: list[CheckResult] = []
    min_len = MBAP_LEN if direction == "resp" else 12
    checks.append(
        CheckResult(
            name="mbap_header_complete",
            passed=len(frame) >= min_len,
            detail=f"got {len(frame)} bytes, need >= {min_len} for {direction}",
        )
    )
    if len(frame) < MBAP_LEN:
        return checks

    tid, pid, length = struct.unpack_from(">HHH", frame, 0)
    unit = frame[6]

    checks.append(
        CheckResult(
            name="protocol_id_zero",
            passed=pid == PROTOCOL_ID,
            detail=f"protocol_id={pid} (Modbus TCP must be 0)",
        )
    )
    checks.append(
        CheckResult(
            name="length_field_consistent",
            passed=length == len(frame) - 6,
            detail=f"length field says {length}, actual bytes after length field: {len(frame) - 6}",
        )
    )
    checks.append(
        CheckResult(
            name="unit_id_in_range",
            passed=0 <= unit <= MAX_UNIT_ID,
            detail=f"unit_id={unit} (valid 0-{MAX_UNIT_ID}, 248-255 reserved)",
        )
    )
    if len(frame) < 8:
        checks.append(
            CheckResult(
                name="function_code_known",
                passed=False,
                detail="frame truncated: missing function code",
            )
        )
        return checks

    fc = frame[7]
    is_exception = bool(fc & EXCEPTION_FLAG)
    base_fc = fc & 0x7F
    checks.append(
        CheckResult(
            name="function_code_known",
            passed=base_fc in KNOWN_FCS,
            detail=f"function_code={fc:#04x}"
            + (f" (exception for fc{base_fc})" if is_exception else ""),
        )
    )

    if is_exception:
        code_known = len(frame) >= 9 and frame[8] in EXCEPTION_CODES
        checks.append(
            CheckResult(
                name="exception_code_known",
                passed=code_known,
                detail=f"exception_code={frame[8]:#04x} ({exception_name(frame[8])})"
                if len(frame) >= 9
                else "missing exception code",
            )
        )
        exact = len(frame) == 9
        checks.append(
            CheckResult(
                name="exception_frame_exact_length",
                passed=exact,
                detail=f"exception response must be exactly 9 bytes, got {len(frame)}",
            )
        )
        return checks

    checks.append(
        CheckResult(
            name="function_code_supported",
            passed=fc in KNOWN_FCS,
            detail=f"fc{fc} "
            + ("M1 支持 (fc01-06)" if fc in KNOWN_FCS else "未支持/非法"),
        )
    )

    if direction == "req":
        checks.append(_check_request_pdu(frame, fc))
    else:
        checks.append(_check_response_pdu(frame, fc))
    return checks


def _check_request_pdu(frame: bytes, fc: int) -> CheckResult:
    """请求 PDU: 固定 4 字节操作数 + 边界检查。"""
    if fc not in KNOWN_FCS:
        return CheckResult(name="request_pdu_valid", passed=False, detail=f"unknown fc{fc}")
    if len(frame) != 12:
        return CheckResult(
            name="request_pdu_valid",
            passed=False,
            detail=f"request frame must be 12 bytes (MBAP7+fc+addr2+op2), got {len(frame)}",
        )
    address, operand = struct.unpack_from(">HH", frame, 8)
    if fc in READ_FCS:
        limit = read_limit(fc)
        ok = 1 <= operand <= limit
        detail = f"address={address}, quantity={operand} (bounds 1-{limit})"
        # 地址 + 数量不能跨过 0xFFFF 上边界 (规范 4.1 节 Read PDU 约束)
        if ok and address + operand > 0x10000:
            ok = False
            detail += f"; address+quantity={address + operand} exceeds 0x10000"
        return CheckResult(name="request_pdu_valid", passed=ok, detail=detail)
    if fc == WRITE_SINGLE_COIL:
        ok = operand in (0x0000, 0xFF00)
        return CheckResult(
            name="request_pdu_valid",
            passed=ok,
            detail=f"fc05 wire value {operand:#06x} must be 0x0000 or 0xFF00",
        )
    return CheckResult(
        name="request_pdu_valid", passed=True, detail=f"address={address}, value={operand}"
    )


def _check_response_pdu(frame: bytes, fc: int) -> CheckResult:
    """响应 PDU: 字节计数与帧长自洽。"""
    if fc in READ_FCS:
        if len(frame) < 9:
            return CheckResult(
                name="response_pdu_valid", passed=False, detail="missing byte count"
            )
        byte_count = frame[8]
        ok = len(frame) == 9 + byte_count
        detail = f"byte_count={byte_count}, data bytes present={len(frame) - 9}"
        if fc in (READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
            even = byte_count % 2 == 0
            ok = ok and even
            detail += "; register read requires even byte_count" if not even else ""
        return CheckResult(name="response_pdu_valid", passed=ok, detail=detail)
    if fc in WRITE_FCS:
        ok = len(frame) == 12
        return CheckResult(
            name="response_pdu_valid",
            passed=ok,
            detail=f"fc{fc} response must be 12 bytes (request echo), got {len(frame)}",
        )
    return CheckResult(
        name="response_pdu_valid", passed=False, detail=f"unknown fc{fc}"
    )


# ---------------------------------------------------------------- 解释


# ---------------------------------------------------------------- 解释


# 解释逻辑与 FINS/MC 共用, 收敛到 protocols/common.py (字节序已参数化);
# 此处 re-export 保持 modbus.codec.interpret_registers 的既有调用面。
from plctap.protocols.common import interpret_registers  # noqa: E402, F401


# ---------------------------------------------------------------- RTU (仅校验/评测)


def crc16(data: bytes) -> int:
    """Modbus RTU CRC-16: poly 0xA001 (反转 0x8005), 初值 0xFFFF, 无终异或。

    纯函数, 供 validate 与评测 CRC 档使用; v1 协议范围仍只有 TCP
    (HANDOFF 决策 9), RTU 不建适配器不做串口 I/O。
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def parse_rtu(frame: bytes, direction: Literal["req", "resp"] = "auto") -> ParseResult:
    """解析 RTU 帧 (addr + fc + PDU + CRC2 小端)。畸形帧记 errors 不抛。

    方向 auto 规则: 异常帧按响应; 8 字节帧按请求 (fc01-06 请求恒 8 字节;
    fc05/06 响应回显同形, 两种解释一致)。例外: fc16 请求最少 11 字节,
    故 8 字节的 fc16 帧必为响应。
    """
    if direction == "auto":
        _fc = frame[1] & 0x7F if len(frame) >= 2 else -1
        if _fc == WRITE_MULTIPLE_REGISTERS:
            # fc16: 请求含数据区 (>=11B), 响应恒 8B 回显
            direction = "resp" if len(frame) == 8 else "req"
        else:
            # fc01-06: 请求恒 8B; fc05/06 响应回显同形, 两种解释一致
            direction = "req" if len(frame) == 8 else "resp"
    errors: list[str] = []
    fields: list[FrameField] = []
    if len(frame) < 4:  # addr1 + fc1 + crc2
        return ParseResult(protocol="modbus", direction=direction, fields=fields, valid=False,
                           errors=[f"frame too short for RTU: {len(frame)} < 4 bytes"])
    addr = frame[0]
    fc = frame[1]
    payload = frame[2:-2]
    fields.append(_field(frame, "address", addr, 0, 1, "从站地址 (RTU)"))
    fields.append(_field(frame, "function_code", fc, 1, 1,
                         f"异常响应 for fc{fc & 0x7F}" if fc & EXCEPTION_FLAG else ""))
    fields.append(_field(frame, "payload", list(payload), 2, len(payload)))
    (crc_wire,) = struct.unpack_from("<H", frame, len(frame) - 2)  # CRC 小端
    crc_calc = crc16(frame[:-2])
    fields.append(_field(frame, "crc", crc_wire, len(frame) - 2, 2,
                         f"computed {crc_calc:#06x}; {'OK' if crc_wire == crc_calc else 'MISMATCH'}"))
    if crc_wire != crc_calc:
        errors.append(f"CRC mismatch: wire {crc_wire:#06x}, computed {crc_calc:#06x}")
    if fc & EXCEPTION_FLAG:
        if len(payload) != 1:
            errors.append(f"exception response payload must be 1 byte, got {len(payload)}")
        elif payload[0] not in EXCEPTION_CODES:
            errors.append(f"unknown exception code {payload[0]:#04x}")
        else:
            fields[-2].note = f"exception {exception_name(payload[0])} for fc{fc & 0x7F}"
        if len(payload) == 1:
            # exception_code 字段与 TCP 解析对齐, 诊断引擎按异常码匹配 KB 时
            # 不必区分 TCP/RTU 轨道
            fields.append(_field(frame, "exception_code", payload[0], 2, 1,
                                 EXCEPTION_CODES.get(payload[0], f"UNKNOWN_0x{payload[0]:02X}")))
        return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=not errors, errors=errors)
    if fc == WRITE_MULTIPLE_REGISTERS:
        if direction == "req":
            # 请求: start(2) + qty(2) + byte_count(1) + data...
            if len(payload) >= 5:
                start = struct.unpack_from(">H", payload, 0)[0]
                qty = struct.unpack_from(">H", payload, 2)[0]
                fields.append(_field(frame, "address", start, 2, 2))
                fields.append(_field(frame, "quantity", qty, 4, 2))
                fields.append(_field(frame, "byte_count", payload[4], 6, 1))
            else:
                errors.append("fc16 request too short")
        else:
            # 响应: 回显 start(2) + qty(2)
            if len(payload) >= 4:
                start = struct.unpack_from(">H", payload, 0)[0]
                qty = struct.unpack_from(">H", payload, 2)[0]
                fields.append(_field(frame, "address", start, 2, 2))
                fields.append(_field(frame, "quantity", qty, 4, 2))
            else:
                errors.append("fc16 response too short")
        return ParseResult(protocol="modbus", direction=direction, fields=fields, valid=not errors, errors=errors)
    if fc not in KNOWN_FCS:
        errors.append(f"unknown function code {fc:#04x}")
        return ParseResult(protocol="modbus", direction=direction, fields=fields, valid=not errors, errors=errors)
    if fc in READ_FCS and direction == "resp":
        if len(payload) < 1:
            errors.append("response truncated: missing byte count")
            return ParseResult(protocol="modbus", direction="resp", fields=fields, valid=False, errors=errors)
        byte_count = payload[0]
        data = payload[1:]
        fields.append(_field(frame, "byte_count", byte_count, 3, 1))
        fields.append(_field(frame, "register_values",
                             [int.from_bytes(data[i:i + 2], "big") for i in range(0, min(byte_count, len(data)) - 1, 2)],
                             4, len(data), "16-bit 大端字值"))
        if len(data) != byte_count:
            errors.append(f"byte_count {byte_count} != data bytes {len(data)}")
    elif direction == "req" and len(payload) != 4:
        errors.append(f"request payload must be 4 bytes (addr2+operand2), got {len(payload)}")
    return ParseResult(protocol="modbus", direction=direction, fields=fields, valid=not errors, errors=errors)


def validate_rtu(frame: bytes, direction: Literal["req", "resp"] = "auto") -> list[CheckResult]:
    """RTU 校验清单: 最短长度、CRC、功能码、payload 形状。"""
    checks: list[CheckResult] = []
    checks.append(CheckResult(name="rtu_min_length", passed=len(frame) >= 4,
                              detail=f"got {len(frame)} bytes, need >= 4 (addr+fc+crc)"))
    if len(frame) < 4:
        return checks
    (crc_wire,) = struct.unpack_from("<H", frame, len(frame) - 2)
    crc_calc = crc16(frame[:-2])
    checks.append(CheckResult(name="rtu_crc_valid", passed=crc_wire == crc_calc,
                              detail=f"wire={crc_wire:#06x}, computed={crc_calc:#06x} (poly 0xA001, LE)"))
    fc = frame[1]
    checks.append(CheckResult(name="function_code_known",
                              passed=(fc & 0x7F) in KNOWN_FCS,
                              detail=f"function_code={fc:#04x}"))
    if direction == "auto":
        # 与 parse_rtu 同规则: fc16 响应恒 8B 回显 (请求含数据区 >=11B), 其余 8B 视作请求
        if (fc & 0x7F) == WRITE_MULTIPLE_REGISTERS:
            direction = "resp" if len(frame) == 8 else "req"
        else:
            direction = "req" if len(frame) == 8 else "resp"
    if fc & EXCEPTION_FLAG:
        checks.append(CheckResult(name="exception_payload_shape",
                                  passed=len(frame) == 5,
                                  detail=f"exception frame must be 5 bytes (addr+fc|0x80+code+crc2), got {len(frame)}"))
    elif direction == "req":
        if fc == WRITE_MULTIPLE_REGISTERS:
            # fc16 请求: addr+fc+start2+qty2+bc1+data(bc)+crc2 -> 总长 9+bc,
            # 且 byte_count 必须等于 qty*2 (此前硬编码 8B 把合法 fc16 请求误报)
            if len(frame) >= 7:
                bc = frame[6]
                qty = int.from_bytes(frame[4:6], "big")
                checks.append(CheckResult(
                    name="request_payload_shape",
                    passed=len(frame) == 9 + bc and bc == qty * 2,
                    detail=f"fc16 request: length {len(frame)} vs 9+byte_count {bc}; "
                           f"byte_count {bc} vs qty*2 {qty*2}"))
            else:
                checks.append(CheckResult(
                    name="request_payload_shape", passed=False,
                    detail=f"fc16 request too short: {len(frame)} bytes, need >= 7"))
        else:
            checks.append(CheckResult(name="request_payload_shape",
                                      passed=len(frame) == 8,
                                      detail=f"read/write request must be 8 bytes, got {len(frame)}"))
    else:
        # 响应形状: 写单点响应 (fc05/06/0f/10) 是 8 字节回显; 读响应帧长
        # 恒为 5 + byte_count (addr+fc+bc+data+crc2)。byte_count 与帧长
        # 自洽是区分真 RTU 响应与 "被硬解成 RTU 的 TCP 帧" 的关键证据 ——
        # 12 字节 TCP 请求当 RTU 响应解时 byte_count 对不上帧长。
        if fc in WRITE_FCS:
            checks.append(CheckResult(name="response_payload_shape", passed=len(frame) == 8,
                                      detail=f"write echo must be 8 bytes, got {len(frame)}"))
        elif fc in READ_FCS:
            bc = frame[2]
            checks.append(CheckResult(name="response_payload_shape", passed=len(frame) == 5 + bc,
                                      detail=f"read response length {len(frame)} != 5 + byte_count {bc:#04x}"))
        else:
            checks.append(CheckResult(name="response_payload_shape", passed=len(frame) >= 6,
                                      detail=f"got {len(frame)} bytes"))
    return checks
