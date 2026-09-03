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
from typing import Literal, Sequence

from plctap.models import ByteOrder, CheckResult, FrameField, ParseResult

# 功能码 (M1 覆盖读 1-4 与单写 5-6; 多写 15/16 留 M3 写闸门)
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6

READ_FCS = (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS)
WRITE_FCS = (WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER)
KNOWN_FCS = READ_FCS + WRITE_FCS

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
    """响应与请求的配对校验 (事务号回显、单元号一致、功能码对应)。"""
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


def interpret_registers(
    raw: Sequence[int],
    datatype: str | None = None,
    byteorder: ByteOrder = "big",
) -> list[float | int]:
    """把寄存器原始值按 datatype 解释 (T4)。

    字节序决策: Modbus 寄存器 16 位内容按规范恒为大端, byteorder 只影响
    32 位 (float32) 的**寄存器对组合顺序**:
    - "big":    高字在前, 字内大端 (ABCD, 最常见)
    - "little": 低字在前, 字内小端 (DCBA)
    常见的字交换 CDAB 等其它组合留待知识库收录后作为独立选项加入,
    M1 只做显式两档, 避免隐式猜测。
    """
    if datatype is None:
        return list(raw)
    if datatype == "uint16":
        return list(raw)
    if datatype == "int16":
        return [v - 0x10000 if v >= 0x8000 else v for v in raw]
    if datatype == "float32":
        if len(raw) % 2 != 0:
            raise ValueError(
                f"float32 needs an even number of registers, got {len(raw)}"
            )
        out: list[float] = []
        for i in range(0, len(raw), 2):
            if byteorder == "big":
                b = raw[i].to_bytes(2, "big") + raw[i + 1].to_bytes(2, "big")
                (f,) = struct.unpack(">f", b)
            elif byteorder == "little":
                b = raw[i].to_bytes(2, "little") + raw[i + 1].to_bytes(2, "little")
                (f,) = struct.unpack("<f", b)
            else:
                raise ValueError(f"unknown byteorder {byteorder!r} (use 'big' or 'little')")
            out.append(f)
        return out
    raise ValueError(
        f"unknown datatype {datatype!r} (supported: uint16, int16, float32)"
    )
