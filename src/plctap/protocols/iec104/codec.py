"""IEC 60870-5-104 帧编解码纯函数 (v0.5.2)。

依据: IEC 60870-5-104:2006 + IEC 60870-5-101 配套 (ASDU 结构一致)。
帧结构两层:
1. APCI (6B): 启动字符 0x68 + APDU 长度 (4-253, 含控制域 4B) + 4 控制域。
   I 格式 (bit0=0, 携带 ASDU): 发送/接收序号各 15bit (低两位 = 0/1);
   S 格式 (bit1=0, bit0=1): 确认序号; U 格式 (bit0=bit1=1): 控制功能
   (STARTDT/STOPDT/TESTFR 的 ACT/CON)。
2. ASDU (I 格式载荷): 类型标识(1) + VSQ(1) + COT(2, 含 P/T 位) + 公共
   地址(2) + 信息对象 (IOA 3B 小端 + 元素 [+ CP56Time2a 7B])。

字节序: IOA/字段小端, 值大端语义按类型定义 —— 与 Modbus 相反, 知识库素材。

v0.5.2 收录 ASDU 类型 (遥信/遥测常用集 + 诊断必需的系统类型):
监视方向 M_SP_NA_1(1)/M_ME_NA_1(9)/M_ME_NB_1(11)/M_ME_NC_1(13) 及带时标
变体 30/34/35/36; 控制方向 C_SC_NA_1(45)/C_IC_NA_1(100)/C_RD_NA_1(102)/
C_CS_NA_1(103)/C_TS_NA_1(104)。未收录类型渲染结构化字段但标 UNKNOWN_TYPE。
"""

from __future__ import annotations

import struct
from typing import Literal

from plctap.models import CheckResult, FrameField, ParseResult
from plctap.protocols.common import interpret_registers  # noqa: F401

START_BYTE = 0x68
APCI_LEN = 6
MAX_APDU_LEN = 253
MIN_APDU_LEN = 4  # U/S 格式: 6B 帧长 = len 字段 4

# ------------------------------------------------------------ U 格式功能码

U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT = 0x13
U_STOPDT_CON = 0x17
U_TESTFR_ACT = 0x43
U_TESTFR_CON = 0x83

U_FUNCTION_NAMES: dict[int, str] = {
    U_STARTDT_ACT: "STARTDT_ACT",
    U_STARTDT_CON: "STARTDT_CON",
    U_STOPDT_ACT: "STOPDT_ACT",
    U_STOPDT_CON: "STOPDT_CON",
    U_TESTFR_ACT: "TESTFR_ACT",
    U_TESTFR_CON: "TESTFR_CON",
}

# ------------------------------------------------------------ ASDU 类型

M_SP_NA_1 = 1   # 单点遥信
M_SP_TB_1 = 30  # 单点遥信 + CP56
M_ME_NA_1 = 9   # 归一化遥测 (NVA 2B)
M_ME_NB_1 = 11  # 标度化遥测 (SVA 2B)
M_ME_NC_1 = 13  # 短浮点遥测 (R32 4B)
M_ME_TD_1 = 34  # 归一化 + CP56
M_ME_TE_1 = 35  # 标度化 + CP56
M_ME_TF_1 = 36  # 短浮点 + CP56
C_SC_NA_1 = 45  # 单点命令
C_IC_NA_1 = 100  # 总召
C_RD_NA_1 = 102  # 读命令
C_CS_NA_1 = 103  # 时钟同步
C_TS_NA_1 = 104  # 测试命令

TYPE_NAMES: dict[int, str] = {
    M_SP_NA_1: "M_SP_NA_1",
    M_SP_TB_1: "M_SP_TB_1",
    M_ME_NA_1: "M_ME_NA_1",
    M_ME_NB_1: "M_ME_NB_1",
    M_ME_NC_1: "M_ME_NC_1",
    M_ME_TD_1: "M_ME_TD_1",
    M_ME_TE_1: "M_ME_TE_1",
    M_ME_TF_1: "M_ME_TF_1",
    C_SC_NA_1: "C_SC_NA_1",
    C_IC_NA_1: "C_IC_NA_1",
    C_RD_NA_1: "C_RD_NA_1",
    C_CS_NA_1: "C_CS_NA_1",
    C_TS_NA_1: "C_TS_NA_1",
}

MONITOR_TYPES = frozenset({1, 9, 11, 13, 30, 34, 35, 36})
# 元素固定长度 (不含 CP56): 遥信 SIQ 1B, 归一化/标度化 3B (值2+品质1),
# 短浮点 5B (值4+品质1), 单点命令 SCO 1B, 总召/读/测试命令 QOI 1B
_ELEMENT_SIZES: dict[int, int] = {
    1: 1, 30: 1, 9: 3, 11: 3, 13: 5, 34: 3, 35: 3, 36: 5, 45: 1,
    100: 1,   # C_IC: IOA(置 0) + QOI —— lib60870 实测总召带 IOA 字段
    102: 0,   # C_RD: 仅 IOA (无限定符)
    103: 7,   # C_CS: CP56Time2a (无 IOA)
    104: 3,   # C_TS: test(1)+tester(2) (无 IOA)
}
# 强制带 CP56Time2a 的类型
_TIME_TAGGED = frozenset({30, 34, 35, 36})
# 无信息对象地址的类型 (元素直接跟随公共地址)
_NO_IOA_TYPES = frozenset({103, 104})
_CP56_LEN = 7

COT_NAMES: dict[int, str] = {
    1: "PERIODIC", 2: "BACKGROUND_SCAN", 3: "SPONTANEOUS", 4: "INITIALIZED",
    5: "REQUEST", 6: "ACTIVATION", 7: "ACTIVATION_CON", 8: "DEACTIVATION",
    9: "DEACTIVATION_CON", 10: "ACTIVATION_TERMINATION", 11: "RETURN_INFO_REMOTE",
    12: "RETURN_INFO_LOCAL", 20: "INTERROGATED_STATION", 21: "INTERROGATED_GROUP_1",
    22: "INTERROGATED_GROUP_2", 23: "INTERROGATED_GROUP_3", 24: "INTERROGATED_GROUP_4",
    25: "INTERROGATED_GROUP_5", 26: "INTERROGATED_GROUP_6", 27: "INTERROGATED_GROUP_7",
    28: "INTERROGATED_GROUP_8", 29: "INTERROGATED_GROUP_9", 30: "INTERROGATED_GROUP_10",
    44: "UNKNOWN_TYPE_ID", 45: "UNKNOWN_COT", 46: "UNKNOWN_CA", 47: "UNKNOWN_IOA",
}

MAX_IOA = 0xFFFFFF  # IOA 3 字节 (低 24 位)


# ------------------------------------------------------------ APCI 层


def build_apci_i(tx_seq: int, rx_seq: int, asdu: bytes) -> bytes:
    """I 格式帧: APCI(6) + ASDU。tx/rx 序号 15bit, 线上 <<1 (低 bit = 0/1)。"""
    if not 0 <= tx_seq <= 0x7FFF or not 0 <= rx_seq <= 0x7FFF:
        raise ValueError(f"sequence numbers must be 0-32767, got tx={tx_seq} rx={rx_seq}")
    apdu_len = 4 + len(asdu)
    if not MIN_APDU_LEN + 1 <= apdu_len <= MAX_APDU_LEN:
        raise ValueError(f"APDU length {apdu_len} out of range 5-253")
    return (
        struct.pack(">BB", START_BYTE, apdu_len)
        + struct.pack("<HH", (tx_seq << 1) & 0xFFFE, (rx_seq << 1) | 0x01)
        + asdu
    )


def build_apci_u(function: int) -> bytes:
    """U 格式帧 (6B): STARTDT/STOPDT/TESTFR 的 ACT/CON。"""
    if function not in U_FUNCTION_NAMES:
        raise ValueError(f"unknown U-format function {function:#04x}")
    return struct.pack(">BBBBBB", START_BYTE, MIN_APDU_LEN, function, 0, 0, 0)


def build_apci_objects(type_id: int, objects: list[tuple[int, list[int]]], cot: int, ca: int,
                       tx_seq: int, rx_seq: int) -> bytes:
    """I 帧 + 多对象 ASDU 一步构建 (钓鱼监听罐头帧用)。"""
    return build_apci_i(tx_seq, rx_seq, build_asdu_objects(type_id, objects, cot, ca))


def build_apci_s(rx_seq: int) -> bytes:
    """S 格式帧 (6B): 监视方向确认 (无需回 S 帧)。"""
    if not 0 <= rx_seq <= 0x7FFF:
        raise ValueError(f"sequence number must be 0-32767, got {rx_seq}")
    return bytes([START_BYTE, MIN_APDU_LEN, 0x01, 0x00]) + struct.pack("<H", (rx_seq << 1) & 0xFFFE)


def apci_format(control: bytes) -> Literal["I", "S", "U"]:
    """按控制域第 1 字节 bit0/bit1 判帧型。"""
    b = control[0]
    if b & 0x01:
        return "U" if b & 0x02 else "S"
    return "I"


def apci_seq_i(control: bytes) -> tuple[int, int]:
    """I 格式 -> (发送序号, 接收序号)。"""
    tx, rx = struct.unpack("<HH", control[0:4])
    return tx >> 1, rx >> 1


def apci_seq_s(control: bytes) -> int:
    """S 格式 -> 确认的接收序号。"""
    (rx,) = struct.unpack("<H", control[2:4])
    return rx >> 1


# ------------------------------------------------------------ ASDU 层


def asdu_vsq_num(vsq: int) -> int:
    """VSQ 低 6 位 = 信息对象数目 (SQ bit7 置位时为序列首地址)。"""
    return vsq & 0x3F


def asdu_vsq_sq(vsq: int) -> bool:
    return bool(vsq & 0x80)


def _ioa_bytes(ioa: int) -> bytes:
    if not 0 <= ioa <= MAX_IOA:
        raise ValueError(f"IOA {ioa} out of range 0-{MAX_IOA}")
    return struct.pack("<I", ioa)[:3]


def _enc_val_u16(v: int) -> bytes:
    if not 0 <= v <= 0xFFFF:
        raise ValueError(f"value {v} out of range 0-65535")
    return struct.pack("<H", v)


def build_asdu_single_point(ioa: int, value: bool, cot: int, ca: int, with_time: bool = False) -> bytes:
    """M_SP_NA_1 (1) / M_SP_TB_1 (30): 单点遥信 SIQ = 值 bit0 + 品质 (未置坏品质)。"""
    type_id = M_SP_TB_1 if with_time else M_SP_NA_1
    obj = _ioa_bytes(ioa) + bytes([0x01 if value else 0x00])
    if with_time:
        obj += b"\x00" * _CP56_LEN  # 占位时间 (build 侧不伪造真实时钟, 时间置 0)
    return _asdu(type_id, 1, cot, ca, obj)


def build_asdu_measured(ioa: int, value: int, kind: Literal["na", "nb", "nc"], cot: int, ca: int) -> bytes:
    """M_ME_NA_1 (9, 归一化 int16) / NB (11, 标度化 int16) / NC (13, 短浮点 bits)。"""
    if kind == "nc":
        type_id, body = M_ME_NC_1, _enc_val_u16(value & 0xFFFF) + _enc_val_u16((value >> 16) & 0xFFFF)
    else:
        type_id = M_ME_NA_1 if kind == "na" else M_ME_NB_1
        body = _enc_val_u16(value)
    return _asdu(type_id, 1, cot, ca, _ioa_bytes(ioa) + body + bytes([0x00]))  # QDS = 良好


def build_asdu_objects(type_id: int, objects: list[tuple[int, list[int]]], cot: int, ca: int) -> bytes:
    """通用多对象 ASDU (SQ=0): objects = [(ioa, 元素原始字节列表)]。

    供钓鱼监听构造罐头监视帧 (与单点构建器同语义, 一个 ASDU 装多个对象)。
    """
    if type_id not in _ELEMENT_SIZES:
        raise ValueError(f"unknown type id {type_id}")
    if not objects:
        raise ValueError("objects must not be empty")
    body = b"".join(_ioa_bytes(ioa) + bytes(elem) for ioa, elem in objects)
    return _asdu(type_id, len(objects), cot, ca, body)


def build_asdu_interrogation(qoi: int = 20, ca: int = 1, cot: int = 6) -> bytes:
    """C_IC_NA_1 (100) 总召: IOA 置 0 + QOI (站总召 QOI=20)。

    IOA 字段实际存在且置 0 —— 与 lib60870 官方实现逐字节比对确认。
    """
    if not 0 <= qoi <= 0xFF:
        raise ValueError(f"QOI {qoi} out of range")
    return _asdu(C_IC_NA_1, 1, cot, ca, _ioa_bytes(0) + bytes([qoi]))


def build_asdu_read(ioa: int, ca: int = 1) -> bytes:
    """C_RD_NA_1 (102) 读单点命令 (COT=5 REQUEST)。"""
    return _asdu(C_RD_NA_1, 1, 5, ca, _ioa_bytes(ioa))


def build_asdu_clock_sync(ca: int = 1) -> bytes:
    """C_CS_NA_1 (103) 时钟同步, 时间字段全 0 (不伪造真实时钟)。"""
    return _asdu(C_CS_NA_1, 1, 6, ca, b"\x00" * _CP56_LEN)


def _asdu(type_id: int, num: int, cot: int, ca: int, objects: bytes) -> bytes:
    if type_id not in _ELEMENT_SIZES:
        raise ValueError(f"unknown type id {type_id}")
    if not 1 <= num <= 0x3F:
        raise ValueError(f"information object count {num} out of range 1-63")
    if not 0 <= ca <= 0xFFFF or not 0 <= cot <= 0x3F:
        raise ValueError(f"common address {ca} or COT {cot} out of range")
    return (
        bytes([type_id, num])
        + struct.pack("<H", cot)
        + struct.pack("<H", ca)
        + objects
    )


# ---------------------------------------------------------------- parse


def _field(frame: bytes, name: str, value: object, offset: int, size: int, note: str = "") -> FrameField:
    return FrameField(name=name, value=value, raw_hex=frame[offset:offset + size].hex(),
                      byte_offset=offset, note=note)


def _decode_values(type_id: int, data: bytes) -> tuple[list[int], list[str]]:
    """按类型解元素值为 16 位寄存器语义 (M_ME_NC 拆成 2 个 16 位字)。"""
    errors: list[str] = []
    if type_id in (1, 30, 45, 100, 102, 104):
        return [data[0] & 0x01], []
    if type_id in (9, 34, 11, 35):
        return [struct.unpack("<H", data[0:2])[0]], []
    if type_id in (13, 36):
        w0, w1 = struct.unpack("<HH", data[0:4])
        return [w1, w0], []  # wire 低字在前 -> 大端字序 [高字, 低字]
    errors.append(f"no value decoding for type {type_id}")
    return [], errors


def parse_asdu(frame: bytes, asdu_offset: int = APCI_LEN, asdu_len: int | None = None) -> ParseResult:
    """解析 ASDU (I 格式载荷)。畸形不抛, errors 留证据。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    body = frame[asdu_offset:asdu_offset + asdu_len] if asdu_len else frame[asdu_offset:]
    if len(body) < 6:
        return ParseResult(protocol="iec104", direction="resp", fields=fields, valid=False,
                           errors=[f"ASDU too short: {len(body)} < 6 bytes"])
    type_id, vsq = body[0], body[1]
    (cot,) = struct.unpack_from("<H", body, 2)
    (ca,) = struct.unpack_from("<H", body, 4)
    fields.append(_field(body, "type_id", type_id, 0, 1,
                         TYPE_NAMES.get(type_id, f"UNKNOWN_TYPE_{type_id}")))
    fields.append(_field(body, "vsq", vsq, 1, 1,
                         f"num={asdu_vsq_num(vsq)} sq={'sequence' if asdu_vsq_sq(vsq) else 'single'}"))
    fields.append(_field(body, "cot", cot & 0x3F, 2, 2,
                         COT_NAMES.get(cot & 0x3F, f"UNKNOWN_COT_{cot & 0x3F}")
                         + (" (P/N 试验位)" if cot & 0x40 else "")))
    fields.append(_field(body, "common_address", ca, 4, 2))
    if type_id not in _ELEMENT_SIZES:
        errors.append(f"unknown type id {type_id} ({len(body) - 6}B objects)")
        return ParseResult(protocol="iec104", direction="resp", fields=fields, valid=False, errors=errors)
    elem_size = _ELEMENT_SIZES[type_id] + (_CP56_LEN if type_id in _TIME_TAGGED else 0)
    has_ioa = type_id not in _NO_IOA_TYPES
    num = asdu_vsq_num(vsq)
    objects = body[6:]
    # SQ=0: 每对象 IOA(3)+元素; SQ=1: 仅首对象带 IOA, 其余连续元素; 无 IOA 类型只有元素
    if not has_ioa:
        expected = num * elem_size            # 无 IOA 类型: 元素直接排
    elif asdu_vsq_sq(vsq):
        expected = 3 + num * elem_size        # SQ=1: 首对象 IOA + 连续元素
    else:
        expected = num * (3 + elem_size)      # SQ=0: 每对象 IOA + 元素
    if len(objects) != expected:
        errors.append(f"objects length {len(objects)} != expected {expected} (num={num}, type {TYPE_NAMES.get(type_id, type_id)})")
        return ParseResult(protocol="iec104", direction="resp", fields=fields, valid=False, errors=errors)
    # 逐对象解 IOA + 值 (SQ=0: 每对象 IOA(3)+元素; SQ=1: 仅首对象带 IOA)
    values: list[int] = []
    ioas: list[int] = []
    sq = asdu_vsq_sq(vsq)
    off = 0
    for i in range(num):
        if has_ioa and (i == 0 or not sq):
            ioa = int.from_bytes(objects[off:off + 3], "little")
            ioas.append(ioa)
            fields.append(_field(body, f"obj{i}_ioa", ioa, 6 + off, 3))
            off += 3
        val_data = objects[off:off + elem_size]
        vals, v_errs = _decode_values(type_id, val_data)
        values.extend(vals)
        errors.extend(v_errs)
        if type_id in (1, 30) and val_data:
            q = val_data[0] >> 1
            if q:
                fields[-1].note = f"SIQ value={val_data[0] & 1} quality_bits={q:#04x}"
        off += elem_size
    if sq and len(ioas) == 1 and num > 1:
        ioas.extend(range(ioas[0] + 1, ioas[0] + num))
    if values:
        ioa_note = (f"IOA {ioas[0]}" + (f"..{ioas[-1]}" if len(ioas) > 1 else "")) if ioas else "无 IOA 类型"
        fields.append(_field(body, "asdu_values", values, 6, 6, f"{num} 个信息对象, {ioa_note}"))
    return ParseResult(protocol="iec104", direction="resp", fields=fields,
                       valid=not errors, errors=errors)


def parse_frame(frame: bytes, direction: Literal["req", "resp", "auto"] = "auto") -> ParseResult:
    """解析完整 APCI 帧 (+ I 格式的 ASDU)。

    direction 仅影响 ParseResult.direction 标注; 帧型由控制域客观判定。
    """
    errors: list[str] = []
    fields: list[FrameField] = []
    if len(frame) < APCI_LEN:
        return ParseResult(protocol="iec104", direction="resp", fields=fields, valid=False,
                           errors=[f"frame too short for APCI: {len(frame)} < 6 bytes"])
    if frame[0] != START_BYTE:
        return ParseResult(protocol="iec104", direction="resp", fields=fields, valid=False,
                           errors=[f"bad start byte {frame[0]:#04x} (expected 0x68)"])
    apdu_len = frame[1]
    fields.append(_field(frame, "start", frame[0], 0, 1))
    fields.append(_field(frame, "apdu_length", apdu_len, 1, 1, "其后字节数 (含 4B 控制域)"))
    if apdu_len < MIN_APDU_LEN or apdu_len > MAX_APDU_LEN:
        errors.append(f"APDU length {apdu_len} out of range 4-253")
        return ParseResult(protocol="iec104", direction="req", fields=fields, valid=False, errors=errors)
    if len(frame) < apdu_len + 2:
        errors.append(f"frame truncated: got {len(frame)}, need {apdu_len + 2}")
        return ParseResult(protocol="iec104", direction="req", fields=fields, valid=False, errors=errors)
    control = frame[2:6]
    fmt = apci_format(control)
    fields.append(_field(frame, "format", fmt, 2, 1))
    if fmt == "I":
        tx, rx = apci_seq_i(control)
        fields.append(_field(frame, "tx_seq", tx, 2, 2, "发送序号"))
        fields.append(_field(frame, "rx_seq", rx, 4, 2, "接收序号"))
        asdu = parse_asdu(frame, APCI_LEN, apdu_len - 4)
        fields.extend(asdu.fields)
        errors.extend(asdu.errors)
        if direction == "auto":
            if len(frame) >= 9:
                t, cot = frame[6], frame[8]
                if t in MONITOR_TYPES:
                    direction = "resp"
                elif t in (45, 46, 47, 48, 100, 102, 103, 104):
                    direction = "resp" if cot in (7, 9, 10) else "req"
                else:
                    direction = "resp"
            else:
                # ASDU 截断读不出 type/cot: 按监视方向兜底 (与未知 type 一致), 截断已在 errors 留证
                direction = "resp"
        return ParseResult(protocol="iec104", direction=direction, fields=fields,
                           valid=not errors, errors=errors)
    if fmt == "S":
        fields.append(_field(frame, "rx_seq_confirmed", apci_seq_s(control), 4, 2, "确认至该接收序号"))
        return ParseResult(protocol="iec104", direction="req", fields=fields,
                           valid=not errors, errors=errors)
    fn = control[0]
    fields.append(_field(frame, "u_function", fn, 2, 1, U_FUNCTION_NAMES.get(fn, f"UNKNOWN_U_{fn:#04x}")))
    if fn not in U_FUNCTION_NAMES:
        # 未知 U 功能码: 方向按主站主动发起兜底 (req), 真实功能码留 raw_hex/note 证据
        errors.append(f"unknown U-function {fn:#04x}")
    return ParseResult(protocol="iec104", direction="req", fields=fields,
                       valid=not errors and len(frame) == 6, errors=errors
                       + ([] if len(frame) == 6 else [f"U-format frame must be 6 bytes, got {len(frame)}"]))


# ---------------------------------------------------------------- validate


def validate_frame(frame: bytes, direction: Literal["req", "resp"] = "resp") -> list[CheckResult]:
    """规范校验清单: 启动字符/长度自洽/帧型合法/ASDU 结构/类型收录。"""
    checks: list[CheckResult] = []
    checks.append(CheckResult(name="start_byte", passed=bool(frame) and frame[0] == START_BYTE,
                              detail=f"start byte {frame[0]:#04x}" if frame else "empty frame"))
    if len(frame) < 2:
        checks.append(CheckResult(name="length_field", passed=False, detail="frame too short"))
        return checks
    apdu_len = frame[1]
    checks.append(CheckResult(name="length_field",
                              passed=MIN_APDU_LEN <= apdu_len <= MAX_APDU_LEN and len(frame) == apdu_len + 2,
                              detail=f"APDU length {apdu_len}, frame {len(frame)} bytes"))
    if len(frame) < 6 or frame[0] != START_BYTE:
        return checks
    fmt = apci_format(frame[2:6])
    checks.append(CheckResult(name="format_known", passed=fmt in ("I", "S", "U"), detail=f"format {fmt}"))
    if fmt == "U":
        checks.append(CheckResult(name="u_frame_shape", passed=len(frame) == 6 and frame[3] == frame[4] == frame[5] == 0,
                                  detail=f"U frame {len(frame)} bytes, fn={frame[2]:#04x}"))
        checks.append(CheckResult(name="u_function_known",
                                  passed=frame[2] in U_FUNCTION_NAMES,
                                  detail=U_FUNCTION_NAMES.get(frame[2], f"unknown {frame[2]:#04x}")))
    elif fmt == "I":
        checks.append(CheckResult(name="i_has_asdu", passed=len(frame) > 6,
                                  detail=f"I frame with {len(frame) - 6}B ASDU"))
        parsed = parse_asdu(frame, APCI_LEN, apdu_len - 4)
        checks.append(CheckResult(name="asdu_structure", passed=parsed.valid,
                                  detail="; ".join(parsed.errors) or "ASDU 结构自洽"))
    return checks
