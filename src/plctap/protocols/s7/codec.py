"""Siemens S7comm 帧编解码纯函数。

依据: S7comm 协议规范 (Wireshark s7comm dissector) + gos7 (robinson/gos7, 404★)。

S7comm 是多层协议:
  TPKT (RFC 1006) 4B: version(1B)=3 | reserved(1B) | total_len(2B BE)
  COTP (ISO 8073) 3B(数据)/22B(连接): len(1B) | pdu_type(1B) | tpdu_nr(1B)
  S7 header 10B: proto_id(1B)=0x32 | rosctr(1B) | redund(2B) | pdu_ref(2B) | param_len(2B BE) | data_len(2B BE)
  S7 parameter / data: 按功能变化

S7 是有状态协议: TCP 连接后需 COTP CR -> CC -> PDU 协商, 之后才能读写。
所有函数不碰 socket (D2): 单测毫秒级。
"""

from __future__ import annotations

import struct
from typing import Literal

from plctap.models import CheckResult, FrameField, ParseResult
from plctap.protocols.common import interpret_registers  # noqa: F401

# ---------------------------------------------------------------- constants

S7_PROTOCOL_ID = 0x32
COTP_DATA_PDU_TYPE = 0xF0
COTP_CR_PDU_TYPE = 0xE0  # Connection Request
COTP_CC_PDU_TYPE = 0xD0  # Connection Confirm (standard)
COTP_CC_ALT = 0xC0  # Connection Confirm (some S7 simulators/implementations)

ROSCR_JOB = 0x01  # Request
ROSCR_ACK = 0x02  # Acknowledgment (no data)
ROSCR_ACK_DATA = 0x03  # Acknowledgment with data
ROSCR_USERDATA = 0x07  # Protocol extensions

FUNC_READ_VAR = 0x04
FUNC_WRITE_VAR = 0x05

COTP_HEADER_LEN = 3  # len(1B) + pdu_type(1B) + tpdu_nr(1B)
S7_HEADER_LEN = 10   # proto_id(1) + rosctr(1) + redund(2) + pdu_ref(2) + param_len(2) + data_len(2)
S7_READ_REQ_LEN = 31  # TPKT(4) + COTP(3) + S7 header(10) + param(2) + item(12)

# S7 area codes
AREA_CODES: dict[str, int] = {
    "I": 0x81,    # Process Inputs (PE)
    "Q": 0x82,    # Process Outputs (PA)
    "M": 0x83,    # Merkers / Memory bits
    "DB": 0x84,   # Data Blocks
    "DI": 0x85,   # Instance Data Blocks
    "L": 0x86,    # Local data
}
AREA_NAMES: dict[int, str] = {v: k for k, v in AREA_CODES.items()}

# Transport sizes
TS_BIT = 0x01
TS_BYTE = 0x02  # Byte/Word/Dword
TS_INT = 0x03
TS_REAL = 0x04

# Return codes
RETURN_CODES: dict[int, str] = {
    0x00: "RESERVED",
    0x01: "RESERVED",
    0x03: "ACCESS_DENIED",
    0x05: "ADDRESS_OUT_OF_RANGE",
    0x06: "INVALID_DATA_TYPE",
    0x07: "NOT_SUPPORTED",
    0x0A: "OBJECT_NOT_FOUND",
    0xFF: "SUCCESS",
}

RETURN_CODE_NAMES = RETURN_CODES


# Request-side dictionaries (parse_request)
FUNCTION_NAMES: dict[int, str] = {
    FUNC_READ_VAR: "Read Var",
    FUNC_WRITE_VAR: "Write Var",
    0xF0: "PDU Negotiation (Setup Communication)",
}

REQUEST_TRANSPORT_SIZES: dict[int, str] = {
    0x01: "BIT",
    0x02: "BYTE/WORD/DWORD",
    0x03: "INT",
    0x04: "REAL",
}


def return_code_name(code: int) -> str:
    return RETURN_CODES.get(code, f"UNKNOWN_{code:#04x}")


def _field(frame: bytes, name: str, value: object, offset: int, size: int, note: str = "") -> FrameField:
    return FrameField(name=name, value=value, raw_hex=frame[offset:offset + size].hex(), byte_offset=offset, note=note)


# ---------------------------------------------------------------- COTP / TPKT

def build_cotp_connect_request(rack: int = 0, slot: int = 1) -> bytes:
    """COTP Connection Request (22 bytes) — S7 PLC 连接第一帧。

    布局对齐 gos7 isoConnectionRequestTelegram:
    TPKT(4B) + COTP length(1B=17) + COTP body(17B) = 22B
    """
    remote_tsap_hi = 0x01
    remote_tsap_lo = (rack << 5) | slot  # e.g., rack=0, slot=1 -> 0x01
    local_tsap_hi = 0x01
    local_tsap_lo = 0x00

    return bytes([
        3, 0, 0, 22,           # TPKT: version=3, total_len=22
        17,                     # COTP length indicator (17 bytes follow)
        COTP_CR_PDU_TYPE,       # 0xE0 = CR
        0, 0,                   # dst_ref = 0
        0, 1,                   # src_ref = 1
        0,                      # class + options
        0xC0,                   # PDU max length param code
        0x01,                   # param len = 1
        0x0A,                   # TPDU size = 1024
        0xC1, 0x02,             # src TSAP param: id=0xC1, len=2
        local_tsap_hi, local_tsap_lo,
        0xC2, 0x02,             # dst TSAP param: id=0xC2, len=2
        remote_tsap_hi, remote_tsap_lo,
    ])


def parse_cotp_connect_response(frame: bytes) -> dict:
    """解析 COTP Connection Confirm。

    宽松模式: 只验证 TPKT 版本和最小长度, 不严格检查 PDU type ——
    某些 S7 模拟器/网关可能返回 CR 回显 (0xE0) 或非标 CC (0xC0)。
    后续 PDU 协商才是真正的协议验证。
    """
    if len(frame) < 11:
        raise ValueError(f"COTP response too short: {len(frame)}")
    tpkt_ver = frame[0]
    if tpkt_ver != 3:
        raise ValueError(f"TPKT version {tpkt_ver} != 3")
    pdu_type = frame[5] if len(frame) > 5 else 0
    return {"pdu_type": pdu_type, "ok": True}


def build_pdu_negotiation(pdu_length: int = 480) -> bytes:
    """S7 PDU 协商请求 (25 bytes)。"""
    tpkt_len = 25
    return (
        struct.pack(">BBH", 3, 0, tpkt_len)
        + bytes([2, COTP_DATA_PDU_TYPE, 0x80])  # COTP
        + bytes([S7_PROTOCOL_ID, ROSCR_JOB])  # S7 header
        + struct.pack(">HH", 0, 0)  # redundancy + pdu_ref
        + struct.pack(">HH", 8, 0)  # param_len=8, data_len=0
        + bytes([0xF0])  # function = negotiate
        + bytes([0x00])  # reserved
        + struct.pack(">HH", 1, 1)  # max_callers=1, max_callees=1 (gos7 convention)
        + struct.pack(">H", pdu_length)  # PDU length at offset 23-24 (BE)
    )


def parse_pdu_negotiation_response(frame: bytes, requested: int = 480) -> int:
    """解析 PDU 协商响应, 返回协商后的 PDU 长度。

    兼容模式: 真实 S7 PLC 返回 27B Ack_Data, PDU 长度在 offset 25-26。
    IoTClient 测试台架/echo server 可能返回与请求等长的回显 (25B),
    此时假定 PDU 长度 = 请求值。
    """
    if len(frame) < 21:
        raise ValueError(f"PDU negotiation response too short: {len(frame)}")
    if len(frame) >= 27:
        rosctr = frame[8]
        if rosctr != ROSCR_ACK_DATA:
            raise ValueError(f"expected Ack_Data, got rosctr {rosctr:#04x}")
        (pdu_len,) = struct.unpack_from(">H", frame, 25)
        if pdu_len <= 0:
            raise ValueError(f"negotiated PDU length {pdu_len} <= 0")
        return pdu_len
    return requested
def build_read_request(
    area: str,
    db_number: int,
    start: int,
    count: int,
    pdu_ref: int,
    transport_size: int = TS_BYTE,
) -> bytes:
    """构造 S7 Read Var 请求 (function 0x04)。

    area: "DB"|"M"|"I"|"Q"|"L"|"DI"
    db_number: DB 块号 (area="DB" 时使用, 其他为 0)
    start: 起始地址 (字节地址, 非位地址)
    count: 读取数量 (字节/字/双字由 transport_size 决定)
    pdu_ref: PDU 引用号 (递增)
    """
    if area not in AREA_CODES:
        raise ValueError(f"unknown S7 area {area!r}; known: {sorted(AREA_CODES)}")
    area_code = AREA_CODES[area]

    # For byte transport, count = number of bytes
    # For word access, caller passes count as number of items, we convert to bytes
    if transport_size == TS_BYTE:
        num_elements = count
    else:
        num_elements = count

    # S7 addresses are bit-addressed: byte_address * 8
    address = start << 3

    # Item spec (12 bytes)
    item = (
        bytes([0x12])  # var_spec
        + bytes([0x0A])  # length of remaining
        + bytes([0x10])  # syntax_id (S7ANY)
        + bytes([transport_size])
        + struct.pack(">H", num_elements)
        + struct.pack(">H", db_number)
        + bytes([area_code])
        + bytes([(address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF])
    )

    param = bytes([FUNC_READ_VAR, 0x01]) + item  # function + 1 item + item spec
    param_len = len(param)

    # S7 header (10 bytes)
    total_len = 4 + 3 + S7_HEADER_LEN + param_len  # TPKT + COTP + S7 header + param
    s7_header = (
        bytes([S7_PROTOCOL_ID, ROSCR_JOB])
        + struct.pack(">HH", 0, pdu_ref)  # redundancy, pdu_reference
        + struct.pack(">HH", param_len, 0)  # param_len, data_len=0 (read has no data)
    )

    body = s7_header + param
    tpkt = struct.pack(">BBH", 3, 0, total_len)  # TPKT len = 4 + COTP(3) + S7 header + param

    return tpkt + bytes([2, COTP_DATA_PDU_TYPE, 0x80]) + body


def parse_read_response(frame: bytes, request: bytes | None = None) -> ParseResult:
    """解析 S7 Read Var 响应 (Ack_Data)。"""
    errors: list[str] = []
    fields: list[FrameField] = []

    if len(frame) < 25:
        return ParseResult(protocol="s7", direction="resp", fields=fields, valid=False,
                           errors=[f"frame too short: {len(frame)} < 25"])

    # TPKT
    tpkt_ver = frame[0]
    if tpkt_ver != 3:
        errors.append(f"TPKT version {tpkt_ver} != 3")
    (tpkt_len,) = struct.unpack_from(">H", frame, 2)
    fields.append(_field(frame, "tpkt_length", tpkt_len, 2, 2, "TPKT 总长度 (BE)"))

    # COTP
    cotp_pdu_type = frame[5]
    fields.append(_field(frame, "cotp_pdu_type", cotp_pdu_type, 5, 1, "0xF0 = Data Transfer"))

    # S7 header
    proto_id = frame[7]
    fields.append(_field(frame, "protocol_id", proto_id, 7, 1, "0x32 = S7comm"))
    rosctr = frame[8]
    fields.append(_field(frame, "rosctr", rosctr, 8, 1, "0x03 = Ack_Data"))
    if rosctr != ROSCR_ACK_DATA:
        errors.append(f"expected Ack_Data (0x03), got rosctr {rosctr:#04x}")
    (pdu_ref,) = struct.unpack_from(">H", frame, 11)
    fields.append(_field(frame, "pdu_reference", pdu_ref, 11, 2))
    (param_len,) = struct.unpack_from(">H", frame, 13)
    fields.append(_field(frame, "parameter_length", param_len, 13, 2))
    (data_len,) = struct.unpack_from(">H", frame, 15)
    fields.append(_field(frame, "data_length", data_len, 15, 2))

    # S7 parameter
    func_offset = 19 if len(frame) > 19 and frame[19] in (FUNC_READ_VAR, FUNC_WRITE_VAR) else 17
    if func_offset == 19:
        # 标准 12B Ack 头: 17-18 是 error class/code
        fields.append(_field(frame, "error_class", frame[17], 17, 1))
        fields.append(_field(frame, "error_code", frame[18], 18, 1))
        if frame[17] != 0 or frame[18] != 0:
            errors.append(f"S7 header error class/code {frame[17]:#04x}/{frame[18]:#04x}")
    func = frame[func_offset]
    fields.append(_field(frame, "function", func, func_offset, 1, "0x04 = Read Var"))
    if func != FUNC_READ_VAR:
        errors.append(f"expected Read Var (0x04), got {func:#04x}")
    # S7 data section: 12B 头从 21 起直接是 return code; 10B 变体 19-20 为保留 00 00
    return_code = frame[21]
    fields.append(_field(frame, "return_code", return_code, 21, 1, return_code_name(return_code)))
    transport_size = frame[22]
    fields.append(_field(frame, "transport_size", transport_size, 22, 1))
    (data_length,) = struct.unpack_from(">H", frame, 23)
    fields.append(_field(frame, "data_length_item", data_length, 23, 2))

    if return_code != 0xFF:
        errors.append(f"S7 return code {return_code:#04x} ({return_code_name(return_code)})")

    # Data bytes start at offset 25
    data = frame[25:25 + data_length]
    word_values = []
    for i in range(0, len(data) - 1, 2):
        word_values.append(struct.unpack_from(">H", data, i)[0])

    fields.append(_field(frame, "word_values", word_values, 25, len(data), "16-bit 大端字值"))

    # Cross-check pdu_ref with request
    if request is not None and len(request) >= 14:
        (req_pdu_ref,) = struct.unpack_from(">H", request, 11)
        if req_pdu_ref != pdu_ref:
            errors.append(f"pdu_reference mismatch: request {req_pdu_ref}, response {pdu_ref}")

    return ParseResult(protocol="s7", direction="resp", fields=fields, valid=not errors, errors=errors)


# ---------------------------------------------------------------- request

def parse_request(frame: bytes) -> ParseResult:
    """解析 S7 Job 请求 (rosctr=0x01): Read/Write Var 与 PDU 协商。

    与 parse_read_response 同风格: 畸形帧不抛错 (除无法定位 S7 头外),
    尽量解析并在 errors 里记录问题, "解析失败的方式"本身是诊断证据。
    地址字段是位地址 (byte_address * 8), 这里同时给出还原后的字节地址。
    """
    errors: list[str] = []
    fields: list[FrameField] = []

    if len(frame) < 17:
        raise ValueError(f"frame too short for TPKT+COTP+S7 header: {len(frame)}")

    # TPKT
    tpkt_ver = frame[0]
    (tpkt_len,) = struct.unpack_from(">H", frame, 2)
    fields.append(_field(frame, "tpkt_version", tpkt_ver, 0, 1, "RFC 1006, need 3"))
    fields.append(_field(frame, "tpkt_total_len", tpkt_len, 2, 2))
    if tpkt_ver != 3:
        errors.append(f"TPKT version {tpkt_ver} != 3")
    if tpkt_len != len(frame):
        errors.append(f"TPKT total_len {tpkt_len} != actual frame length {len(frame)}")

    # COTP
    fields.append(_field(frame, "cotp_len", frame[4], 4, 1, "bytes following this one"))
    fields.append(_field(frame, "cotp_pdu_type", f"0x{frame[5]:02X}", 5, 1, "0xF0 = DT data"))
    if frame[5] != COTP_DATA_PDU_TYPE:
        errors.append(f"COTP pdu_type {frame[5]:#04x} != 0xF0 (not a DT data frame)")

    # S7 header
    fields.append(_field(frame, "s7_protocol_id", f"0x{frame[7]:02X}", 7, 1, "0x32 = S7comm"))
    if frame[7] != S7_PROTOCOL_ID:
        errors.append(f"S7 protocol id {frame[7]:#04x} != 0x32")
    rosctr = frame[8]
    fields.append(_field(frame, "rosctr", f"0x{rosctr:02X}", 8, 1, "0x01 = Job request"))
    if rosctr != ROSCR_JOB:
        errors.append(f"rosctr {rosctr:#04x} != 0x01 (not a Job request)")
    (redund,) = struct.unpack_from(">H", frame, 9)
    fields.append(_field(frame, "redundancy_ident", redund, 9, 2))
    (pdu_ref,) = struct.unpack_from(">H", frame, 11)
    fields.append(_field(frame, "pdu_reference", pdu_ref, 11, 2, "响应帧需回带同一引用号"))
    (param_len,) = struct.unpack_from(">H", frame, 13)
    fields.append(_field(frame, "param_len", param_len, 13, 2))
    (data_len,) = struct.unpack_from(">H", frame, 15)
    fields.append(_field(frame, "data_len", data_len, 15, 2))

    if param_len < 2 or 17 + param_len > len(frame):
        errors.append(f"param section invalid: param_len={param_len}, frame={len(frame)}B")
        return ParseResult(protocol="s7", direction="req", fields=fields, valid=not errors, errors=errors)

    func_offset = 19 if len(frame) > 19 and frame[19] == FUNC_READ_VAR else 17
    func = frame[func_offset]
    fields.append(_field(frame, "function", func, func_offset, 1, "0x04 = Read Var"))
    if func in (FUNC_READ_VAR, FUNC_WRITE_VAR):
        item_count = frame[18]
        fields.append(_field(frame, "item_count", item_count, 18, 1))
        offset = 19
        for i in range(item_count):
            if offset + 12 > len(frame):
                errors.append(f"item {i} truncated (need 12B at offset {offset})")
                break
            if frame[offset] != 0x12 or frame[offset + 1] != 0x0A:
                errors.append(f"item {i} header invalid: {frame[offset]:#04x},{frame[offset + 1]:#04x} != 12,0A")
                break
            syntax_id = frame[offset + 2]
            fields.append(_field(frame, f"item{i}_syntax_id", f"0x{syntax_id:02X}", offset + 2, 1, "0x10 = S7ANY"))
            ts = frame[offset + 3]
            fields.append(_field(frame, f"item{i}_transport_size", f"0x{ts:02X}", offset + 3, 1, REQUEST_TRANSPORT_SIZES.get(ts, "unknown")))
            (num_elements,) = struct.unpack_from(">H", frame, offset + 4)
            fields.append(_field(frame, f"item{i}_length", num_elements, offset + 4, 2, "元素个数 (BYTE 时=字节数)"))
            (db_number,) = struct.unpack_from(">H", frame, offset + 6)
            fields.append(_field(frame, f"item{i}_db_number", db_number, offset + 6, 2))
            area = frame[offset + 8]
            fields.append(_field(frame, f"item{i}_area", f"0x{area:02X}", offset + 8, 1, AREA_NAMES.get(area, "unknown")))
            (addr24,) = struct.unpack_from(">I", b"\x00" + frame[offset + 9:offset + 12], 0)
            byte_addr = addr24 >> 3
            bit_addr = addr24 & 0x07
            fields.append(_field(frame, f"item{i}_byte_address", byte_addr, offset + 9, 3,
                                 f"位地址 0x{addr24:06X} 还原: 字节 {byte_addr}, 位 {bit_addr}"))
            if area == AREA_CODES["DB"]:
                label = f"DB{db_number}.DBB{byte_addr}"
            else:
                label = f"{AREA_NAMES.get(area, '?')}{byte_addr}"
            fields.append(_field(frame, f"item{i}_address", label, offset, 12, "解析后的可读地址"))
            offset += 12

        if func == FUNC_WRITE_VAR and data_len > 0:
            d = frame[offset:]
            if len(d) < data_len:
                errors.append(f"write data truncated: have {len(d)}, need {data_len}")
            else:
                wd_ts = d[1]
                (bits,) = struct.unpack_from(">H", d, 2)
                nbytes = bits // 8
                fields.append(_field(frame, "write_data_transport_size", f"0x{wd_ts:02X}", offset + 1, 1, REQUEST_TRANSPORT_SIZES.get(wd_ts, "unknown")))
                fields.append(_field(frame, "write_data_len_bits", bits, offset + 2, 2))
                fields.append(_field(frame, "write_data", list(d[4:4 + nbytes]), offset + 4, nbytes, "写入的原始字节"))

    elif func == 0xF0 and param_len >= 8:
        (pdu_len_req,) = struct.unpack_from(">H", frame, 23)
        fields.append(_field(frame, "pdu_length_requested", pdu_len_req, 23, 2, "请求协商的 PDU 上限"))

    return ParseResult(protocol="s7", direction="req", fields=fields, valid=not errors, errors=errors)


# ---------------------------------------------------------------- write


def build_write_request(
    area: str,
    db_number: int,
    start: int,
    values: list[int],
    pdu_ref: int,
    transport_size: int = TS_BYTE,
) -> bytes:
    """构造 S7 Write Var 请求 (function 0x05)。"""
    if area not in AREA_CODES:
        raise ValueError(f"unknown S7 area {area!r}; known: {sorted(AREA_CODES)}")
    area_code = AREA_CODES[area]

    num_elements = len(values) if transport_size != TS_BYTE else sum(2 for _ in values)  # words -> bytes
    address = start << 3

    # Data section: return_code + transport_size + length + data
    data_bytes = b"".join(struct.pack(">H", v) for v in values)
    data_section = (
        bytes([0x00, 0x03])  # reserved(0x00), transport_size for write = 0x03 (INT) or 0x04
        + struct.pack(">H", len(data_bytes) * 8)  # length in bits
        + data_bytes
    )

    # Item spec (12 bytes)
    item = (
        bytes([0x12, 0x0A, 0x10])
        + bytes([transport_size])
        + struct.pack(">H", num_elements)
        + struct.pack(">H", db_number)
        + bytes([area_code])
        + bytes([(address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF])
    )

    param = bytes([FUNC_WRITE_VAR, 0x01]) + item
    param_len = len(param)
    data_len = len(data_section)

    s7_header = (
        bytes([S7_PROTOCOL_ID, ROSCR_JOB])
        + struct.pack(">HH", 0, pdu_ref)
        + struct.pack(">HH", param_len, data_len)
    )

    body = s7_header + param + data_section
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(body) + 3)  # +3 for COTP

    return tpkt + bytes([2, COTP_DATA_PDU_TYPE, 0x80]) + body


def parse_write_response(frame: bytes, request: bytes | None = None) -> dict:
    """解析 S7 Write Var 响应 (Ack_Data)。返回 {"ok": bool, "return_code": int}。"""
    if len(frame) < 22:
        raise ValueError(f"write response too short: {len(frame)}")
    rosctr = frame[8]
    if rosctr != ROSCR_ACK_DATA:
        raise ValueError(f"expected Ack_Data, got rosctr {rosctr:#04x}")
    return_code = frame[21]
    return {"ok": return_code == 0xFF, "return_code": return_code}


# ---------------------------------------------------------------- validate


def validate_frame(frame: bytes, direction: Literal["req", "resp"] = "resp") -> list[CheckResult]:
    """S7 帧校验清单。"""
    checks: list[CheckResult] = []
    checks.append(CheckResult(name="min_length", passed=len(frame) >= 25, detail=f"got {len(frame)}, need >= 25"))
    if len(frame) < 7:
        return checks
    checks.append(CheckResult(name="tpkt_version", passed=frame[0] == 3, detail=f"version={frame[0]} (need 3)"))
    if len(frame) < 17:
        return checks
    proto_id = frame[7]
    checks.append(CheckResult(name="s7_protocol_id", passed=proto_id == S7_PROTOCOL_ID, detail=f"id={proto_id:#04x} (need 0x32)"))
    rosctr = frame[8]
    expected = ROSCR_JOB if direction == "req" else ROSCR_ACK_DATA
    checks.append(CheckResult(name="rosctr", passed=rosctr == expected, detail=f"rosctr={rosctr:#04x} (expect {expected:#04x})"))
    if len(frame) >= 18:
        valid_funcs = {FUNC_READ_VAR, FUNC_WRITE_VAR}
        # Ack_Data 标准头 12B -> 功能码在 19; Job/10B 头 -> 在 17
        func_offset = 19 if len(frame) > 19 and frame[19] in valid_funcs else 17
        func = frame[func_offset]
        checks.append(CheckResult(name="function_valid", passed=func in valid_funcs, detail=f"function={func:#04x}"))
    if len(frame) >= 22:
        rc = frame[21]
        checks.append(CheckResult(name="return_code", passed=rc == 0xFF, detail=f"return_code={rc:#04x} ({return_code_name(rc)})"))
    return checks

