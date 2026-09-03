"""Mitsubishi MELSEC MC 协议 3E 帧编解码纯函数 (M2, 仅二进制模式)。

依据: MELSEC Ethernet 接口手册 (SH-080848) QCPU 3E 帧格式。
帧结构 (二进制, 全小端 —— 与 Modbus/FINS 相反, 知识库核心素材):
  副头部 0x5000 (LE) | 网络号1B | PC号1B | 目标模块I/O 2B | 目标模块站号1B
  | 监视定时器 2B | 请求数据长度 2B LE | 请求数据
请求: 数据 = 命令 2B + 子命令 2B + 参数。0x0401 = 批量读(字单位)。
响应: 数据 = 结束代码 2B LE + 数据。

ASCII 3E/4E 帧明确不做 (BUILD.md 第 3 节)。结束代码映射只收录常见项,
未收录渲染 UNKNOWN_0xXXXX; 完整表见 CPU 手册。
"""

from __future__ import annotations

import struct
from typing import Literal

from plctap.models import CheckResult, FrameField, ParseResult
from plctap.protocols.common import interpret_registers  # noqa: F401

SUBHEADER = 0x5000
SUBHEADER_BYTES = b"\x00\x50"  # 小端序列化
FRAME_HEADER_LEN = 11  # 副头部2 + 网络1 + PC1 + I/O2 + 站号1 + 定时器2 + 数据长2

CMD_BATCH_READ_WORD = 0x0401
CMD_BATCH_WRITE_WORD = 0x1401  # M3 写闸门用
SUBCOMMAND_WORD_UNITS = 0x0000

# 软元件代码 (二进制模式, ASCII 字符码); ZR 文件寄存器等特殊代码暂不收录
DEVICE_CODES: dict[str, int] = {
    "X": 0x58,  # 输入 (位)
    "Y": 0x59,  # 输出 (位)
    "B": 0x42,  # 链接继电器 (位)
    "W": 0x57,  # 链接寄存器 (字)
    "M": 0x4D,  # 内部继电器 (位)
    "D": 0x44,  # 数据寄存器 (字)
    "R": 0x52,  # 文件寄存器 (字)
}
DEVICE_CODE_NAMES: dict[int, str] = {v: k for k, v in DEVICE_CODES.items()}

# 位软元件 (X/Y/B/M) 以字单位读取: 每字含 16 点; 点位设备读取按字解释
BIT_DEVICES = {"X", "Y", "B", "M"}

END_CODES: dict[int, str] = {
    0x0000: "NORMAL_COMPLETION",
    # 以下为 QJ71E71 手册常见项; "常见含义" 以手册为准, 未收录的一律 UNKNOWN
    0xC04F: "DEVICE_NUMBER_OUT_OF_RANGE",  # 软元件号超出允许范围 (常见)
    0xC059: "DATA_CODE_ERROR",  # 数据代码错误 (常见)
    0xC0D8: "ACCESS_FORBIDDEN",  # 访问被禁止 (常见)
}

MAX_READ_POINTS = 960  # 3E 二进制一次通信可读点数上限 (QCPU 默认)

MONITOR_TIMER_VALUES = (0, 1, 2, 10, 11)  # 无限等待/1单位/10单位/1s/1s


def end_code_name(code: int) -> str:
    return END_CODES.get(code, f"UNKNOWN_{code:#06x}")


def _field(frame: bytes, name: str, value: object, offset: int, size: int, note: str = "") -> FrameField:
    return FrameField(
        name=name,
        value=value,
        raw_hex=frame[offset : offset + size].hex(),
        byte_offset=offset,
        note=note,
    )


def _header(
    network: int, pc: int, module_io: int, module_station: int, timer: int, data_len: int
) -> bytes:
    """9B 帧头 + 2B 请求数据长度 (全部小端)。"""
    return (
        SUBHEADER_BYTES
        + bytes([network, pc])
        + struct.pack("<H", module_io)
        + bytes([module_station])
        + struct.pack("<H", timer)
        + struct.pack("<H", data_len)
    )


# ---------------------------------------------------------------- build


def build_read_request(
    device: str,
    head_device: int,
    device_count: int,
    network: int = 0,
    pc: int = 0,
    module_io: int = 0x03FF,
    module_station: int = 0,
    timer: int = 0,
    subcommand: int = SUBCOMMAND_WORD_UNITS,
) -> bytes:
    """构造 0401 批量读(字单位)请求帧。

    位软元件 (X/Y/B/M) 按字单位读: head_device 为起始点号, device_count
    为点数, 响应每字含 16 点 (N 点 = ceil(N/16) 字)。
    """
    if device not in DEVICE_CODES:
        raise ValueError(
            f"unknown device {device!r}; known: {sorted(DEVICE_CODES)} (ZR 等特殊软元件暂不支持)"
        )
    if subcommand != SUBCOMMAND_WORD_UNITS:
        raise ValueError(f"only word-units subcommand 0x0000 supported, got {subcommand:#06x}")
    for name, v in (
        ("network", network),
        ("pc", pc),
        ("module_station", module_station),
    ):
        if not 0 <= v <= 0xFF:
            raise ValueError(f"{name} {v} out of range 0-255")
    if not 0 <= module_io <= 0xFFFF:
        raise ValueError(f"module_io {module_io} out of range")
    if timer not in MONITOR_TIMER_VALUES:
        raise ValueError(f"timer {timer} not in {MONITOR_TIMER_VALUES}")
    if not 0 <= head_device <= 0xFFFFFF:
        raise ValueError(f"head_device {head_device} out of range 0-16777215 (3B)")
    if not 1 <= device_count <= MAX_READ_POINTS:
        raise ValueError(f"device_count {device_count} out of range 1-{MAX_READ_POINTS}")
    code = DEVICE_CODES[device]
    # 位软元件按字单位读时数量字段仍为点数, 响应按 ceil(点数/16) 字返回 (手册 3.1 节)
    data = (
        struct.pack("<HH", CMD_BATCH_READ_WORD, subcommand)
        + bytes([code])
        + struct.pack("<I", head_device)[:3]  # 3B 小端
        + struct.pack("<H", device_count)
    )
    return _header(network, pc, module_io, module_station, timer, len(data)) + data


# ---------------------------------------------------------------- parse


def _parse_header(frame: bytes) -> tuple[int, int, int, int, int, int, int]:
    """解析 11B 头部, 返回 (subheader, network, pc, module_io, station, timer, datalen)。"""
    if len(frame) < FRAME_HEADER_LEN:
        raise ValueError(f"frame too short for 3E header: {len(frame)} < {FRAME_HEADER_LEN}")
    (subheader,) = struct.unpack_from("<H", frame, 0)
    network, pc = frame[2], frame[3]
    (module_io,) = struct.unpack_from("<H", frame, 4)
    station = frame[6]
    (timer,) = struct.unpack_from("<H", frame, 7)
    (data_len,) = struct.unpack_from("<H", frame, 9)
    return subheader, network, pc, module_io, station, timer, data_len


def _header_fields(frame: bytes, fields: list[FrameField]) -> None:
    subheader, network, pc, module_io, station, timer, data_len = _parse_header(frame)
    fields.append(_field(frame, "subheader", subheader, 0, 2, "3E 二进制帧标识 0x5000"))
    fields.append(_field(frame, "network_number", network, 2, 1))
    fields.append(_field(frame, "pc_number", pc, 3, 1))
    fields.append(_field(frame, "module_io", module_io, 4, 2, "目标模块 I/O 号"))
    fields.append(_field(frame, "module_station", station, 6, 1))
    fields.append(_field(frame, "monitoring_timer", timer, 7, 2))
    fields.append(_field(frame, "data_length", data_len, 9, 2, "其后数据字节数 (小端)"))


def parse_request(frame: bytes) -> ParseResult:
    errors: list[str] = []
    fields: list[FrameField] = []
    try:
        subheader, _net, _pc, _io, _st, _timer, data_len = _parse_header(frame)
    except ValueError as e:
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=[str(e)])
    _header_fields(frame, fields)
    if subheader != SUBHEADER:
        errors.append(f"subheader {subheader:#06x} != 0x5000 (only 3E binary supported)")
    data = frame[FRAME_HEADER_LEN:]
    if data_len != len(data):
        errors.append(f"data_length {data_len} != actual data bytes {len(data)}")
    if len(data) < 4:
        errors.append("request data too short for command+subcommand")
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=errors)
    cmd, subcmd = struct.unpack_from("<HH", data, 0)
    fields.append(_field(frame, "command", cmd, FRAME_HEADER_LEN, 2))
    fields.append(_field(frame, "subcommand", subcmd, FRAME_HEADER_LEN + 2, 2))
    if cmd != CMD_BATCH_READ_WORD:
        errors.append(f"unsupported command {cmd:#06x} (only 0401 batch read in M2)")
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=errors)
    if len(data) < 7:
        errors.append("read request truncated: need device code(1)+head(3)+count(2)")
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=errors)
    code = data[4]
    head = int.from_bytes(data[5:8], "little")
    count = int.from_bytes(data[8:10], "little") if len(data) >= 10 else 0
    fields.append(_field(frame, "device_code", code, FRAME_HEADER_LEN + 4, 1, DEVICE_CODE_NAMES.get(code, "")))
    fields.append(_field(frame, "head_device", head, FRAME_HEADER_LEN + 5, 3))
    if len(data) >= 10:
        fields.append(_field(frame, "device_count", count, FRAME_HEADER_LEN + 8, 2))
    else:
        errors.append("read request truncated: missing device_count")
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=errors)
    if code not in DEVICE_CODE_NAMES:
        errors.append(f"unknown device code {code:#04x}")
    if not 1 <= count <= MAX_READ_POINTS:
        errors.append(f"device_count {count} out of range 1-{MAX_READ_POINTS}")
    return ParseResult(protocol="melsec", direction="req", fields=fields, valid=not errors, errors=errors)


def parse_response(frame: bytes, request: bytes | None = None) -> ParseResult:
    """解析 3E 响应帧。request 提供时校验头部回显 (网络号/PC号/模块I/O) 与
    数据长度自洽 —— BUILD.md 注入清单的"副头部长度不符/结束代码非 0"在此暴露。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    try:
        subheader, _net, _pc, _io, _st, _timer, data_len = _parse_header(frame)
    except ValueError as e:
        return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=False, errors=[str(e)])
    _header_fields(frame, fields)
    if subheader != SUBHEADER:
        errors.append(f"subheader {subheader:#06x} != 0x5000 (only 3E binary supported)")
    data = frame[FRAME_HEADER_LEN:]
    if data_len != len(data):
        errors.append(f"data_length {data_len} != actual data bytes {len(data)}")
    if len(data) < 2:
        errors.append("response data too short for end code")
        return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=False, errors=errors)
    (end_code,) = struct.unpack_from("<H", data, 0)
    fields.append(_field(frame, "end_code", end_code, FRAME_HEADER_LEN, 2, end_code_name(end_code)))

    if request is not None:
        errors.extend(_cross_check(frame, request))

    if end_code != 0x0000:
        if len(data) > 2:
            errors.append(f"nonzero end code but {len(data) - 2} trailing data bytes present")
        return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=not errors, errors=errors)
    values_raw = data[2:]
    if len(values_raw) % 2 != 0:
        errors.append(f"odd data length {len(values_raw)} for 16-bit word read")
    values = [int.from_bytes(values_raw[i : i + 2], "little") for i in range(0, len(values_raw) - 1, 2)]
    fields.append(
        _field(frame, "word_values", values, FRAME_HEADER_LEN + 2, len(values_raw), "16-bit 小端字值")
    )
    if request is not None and values:
        # 数据量与请求 count 核对 (位软元件向上取整到字)
        try:
            req = parse_request(request)
            cnt_f = next((f.value for f in req.fields if f.name == "device_count"), None)
            dev_f = next((f.value for f in req.fields if f.name == "device_code"), None)
            if isinstance(cnt_f, int) and isinstance(dev_f, int):
                dev_name = DEVICE_CODE_NAMES.get(dev_f)
                words = (cnt_f + 15) // 16 if dev_name in BIT_DEVICES else cnt_f
                if len(values) < words:
                    errors.append(f"data short: requested {words} words, got {len(values)}")
        except Exception:  # noqa: BLE001  # 请求畸形时跳过数据量核对
            pass
    return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=not errors, errors=errors)


def _cross_check(frame: bytes, request: bytes) -> list[str]:
    problems: list[str] = []
    try:
        r = _parse_header(request)
        s = _parse_header(frame)
    except ValueError:
        return problems
    # 头部回显: 网络号/PC号/模块I/O/站号应与请求一致 (3E 规范)
    if r[1] != s[1]:
        problems.append(f"network_number mismatch: request {r[1]}, response {s[1]}")
    if r[2] != s[2]:
        problems.append(f"pc_number mismatch: request {r[2]}, response {s[2]}")
    if r[3] != s[3]:
        problems.append(f"module_io mismatch: request {r[3]:#06x}, response {s[3]:#06x}")
    return problems


# ---------------------------------------------------------------- validate


def validate_frame(frame: bytes, direction: Literal["req", "resp"] = "resp") -> list[CheckResult]:
    """3E 校验清单: 帧长、副头部、数据长度一致性、命令/软元件代码、结束代码。"""
    checks: list[CheckResult] = []
    checks.append(
        CheckResult(
            name="frame_header_complete",
            passed=len(frame) >= FRAME_HEADER_LEN,
            detail=f"got {len(frame)} bytes, need >= {FRAME_HEADER_LEN}",
        )
    )
    if len(frame) < FRAME_HEADER_LEN:
        return checks
    subheader, _net, _pc, _io, _st, _timer, data_len = _parse_header(frame)
    checks.append(
        CheckResult(
            name="subheader_3e_binary",
            passed=subheader == SUBHEADER,
            detail=f"subheader={subheader:#06x} (0x5000 = 3E binary)",
        )
    )
    checks.append(
        CheckResult(
            name="data_length_consistent",
            passed=data_len == len(frame) - FRAME_HEADER_LEN,
            detail=f"data_length={data_len}, actual data bytes={len(frame) - FRAME_HEADER_LEN}",
        )
    )
    data = frame[FRAME_HEADER_LEN:]
    if direction == "req":
        if len(data) >= 2:
            (cmd,) = struct.unpack_from("<H", data, 0)
            checks.append(
                CheckResult(
                    name="command_supported",
                    passed=cmd == CMD_BATCH_READ_WORD,
                    detail=f"command={cmd:#06x} (0x0401 = batch read word units)",
                )
            )
        else:
            checks.append(CheckResult(name="command_supported", passed=False, detail="missing command"))
    else:
        if len(data) >= 2:
            (end_code,) = struct.unpack_from("<H", data, 0)
            checks.append(
                CheckResult(
                    name="end_code_known",
                    passed=end_code in END_CODES,
                    detail=f"end_code={end_code:#06x} ({end_code_name(end_code)})",
                )
            )
        else:
            checks.append(CheckResult(name="end_code_known", passed=False, detail="missing end code"))
    return checks
