# -*- coding: utf-8 -*-
"""Mitsubishi MELSEC MC 协议 (QnA 兼容 3E/4E 帧) codec。

线上格式依据 (与 pymcprotocol、开源 MC 从站、三菱 SLMP 手册交叉核对):
  - 子头部线上为大端: 3E 请求 0x5000 -> 50 00, 3E 响应 0xD000 -> D0 00,
    4E 请求 0x5400 -> 54 00, 4E 响应 0xD400 -> D4 00。
  - 其余多字节整数字段一律小端。
  - 请求帧: 副头部 + 路由5B + 请求数据长度2B + 监视定时器2B + 请求数据。
    请求数据长度 = 数据长字段之后至帧尾的字节数 (定时器 + 请求数据)。
  - 响应帧: 副头部 + 路由5B + 响应数据长度2B + 结束代码2B + 数据。
    响应数据长度 = 结束代码 + 数据 的总字节数。响应帧无监视定时器字段。
  - 软元件项: 软元件号(3B 小端) + 软元件代码(1B) + 点数(2B 小端)。
    二进制软元件代码: D=0xA8, X=0x9C, Y=0x9D, M=0x90, B=0xA0, W=0xB4, R=0xAF;
    ASCII 模式软元件代码为 2 字符 ("D*" 等)。
  - ASCII 帧: 所有字段按大写十六进制 ASCII 序列化 (1 字节 = 2 字符)。
"""

from __future__ import annotations

import struct
from typing import Literal

from plctap.models import CheckResult, FrameField, ParseResult
from plctap.protocols.common import interpret_registers  # noqa: F401

SUBHEADER = 0x5000
SUBHEADER_BYTES = b"\x50\x00"  # 3E 请求副头部 (线上大端)
RESPONSE_SUBHEADER_BYTES = b"\xD0\x00"  # 3E 响应副头部
SUBHEADER_4E_BYTES = b"\x54\x00"  # 4E 请求副头部
RESPONSE_SUBHEADER_4E_BYTES = b"\xD4\x00"  # 4E 响应副头部
FRAME_HEADER_LEN = 11  # 副头部2 + 网络1 + PC1 + I/O2 + 站号1 + 数据长2 + 定时器2

CMD_BATCH_READ_WORD = 0x0401
CMD_BATCH_WRITE_WORD = 0x1401
SUBCOMMAND_WORD_UNITS = 0x0000

# 软元件代码 (二进制模式 1B); ZR 文件寄存器等特殊代码暂不收录
DEVICE_CODES: dict[str, int] = {
    "X": 0x9C,
    "Y": 0x9D,
    "B": 0xA0,
    "W": 0xB4,
    "M": 0x90,
    "D": 0xA8,
    "R": 0xAF,
}
# ASCII 模式软元件代码 (2 字符, '*' 填充)
ASCII_DEVICE_CODES: dict[str, str] = {k: f"{k}*" for k in DEVICE_CODES}
# ASCII 模式软元件号的进制 (X/Y/B/W 十六进制, D/M/R 十进制; 见 SLMP 手册)
ASCII_DEVICE_BASES: dict[str, int] = {"X": 16, "Y": 16, "B": 16, "W": 16, "M": 10, "D": 10, "R": 10}
DEVICE_CODE_NAMES: dict[int, str] = {v: k for k, v in DEVICE_CODES.items()}
ASCII_DEVICE_CODE_NAMES: dict[str, str] = {v: k for k, v in ASCII_DEVICE_CODES.items()}

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

MONITOR_TIMER_VALUES = (0, 1, 2, 4, 10, 11)  # 无限等待/1单位/10单位/4单位(1s)/1s/1s


# ---------------------------------------------------------------- frame formats

FRAME_3E_BINARY = "3e_binary"
FRAME_3E_ASCII = "3e_ascii"
FRAME_4E_BINARY = "4e_binary"
FRAME_4E_ASCII = "4e_ascii"
FRAME_FORMATS = (FRAME_3E_BINARY, FRAME_3E_ASCII, FRAME_4E_BINARY, FRAME_4E_ASCII)

# 请求/响应副头部值 (线上大端: 50 00 / D0 00 / 54 00 / D4 00)
_REQ_SUBHEADERS: dict[str, int] = {
    FRAME_3E_BINARY: 0x5000,
    FRAME_3E_ASCII: 0x5000,
    FRAME_4E_BINARY: 0x5400,
    FRAME_4E_ASCII: 0x5400,
}
_RESP_SUBHEADERS: dict[str, int] = {
    FRAME_3E_BINARY: 0xD000,
    FRAME_3E_ASCII: 0xD000,
    FRAME_4E_BINARY: 0xD400,
    FRAME_4E_ASCII: 0xD400,
}
_SUBHEADERS: dict[str, int] = _REQ_SUBHEADERS  # 兼容旧引用 (请求侧)

# 帧头长度 == 响应数据起始前的公共头部
_HEADER_LENS: dict[str, int] = {
    FRAME_3E_BINARY: 11,
    FRAME_3E_ASCII: 22,
    FRAME_4E_BINARY: 15,
    FRAME_4E_ASCII: 30,
}

# 请求监视定时器 / 响应结束代码 的偏移 (同位置)
_END_OFFSETS: dict[str, int] = {
    FRAME_3E_BINARY: 9,
    FRAME_3E_ASCII: 18,
    FRAME_4E_BINARY: 13,
    FRAME_4E_ASCII: 26,
}

# 响应数据起始偏移 (= 结束代码之后)
_DATA_START_OFFSETS: dict[str, int] = {
    FRAME_3E_BINARY: 11,
    FRAME_3E_ASCII: 22,
    FRAME_4E_BINARY: 15,
    FRAME_4E_ASCII: 30,
}

# (请求数据长度 / 响应数据长度) 字段偏移
_DATALEN_OFFSETS: dict[str, int] = {
    FRAME_3E_BINARY: 7,
    FRAME_3E_ASCII: 14,
    FRAME_4E_BINARY: 11,
    FRAME_4E_ASCII: 22,
}


def _is_ascii(fmt: str) -> bool:
    return fmt in (FRAME_3E_ASCII, FRAME_4E_ASCII)


def _is_4e(fmt: str) -> bool:
    return fmt in (FRAME_4E_BINARY, FRAME_4E_ASCII)


def _enc_ascii(value: int, width_bytes: int) -> bytes:
    """Encode int as uppercase ASCII hex, width_bytes * 2 chars."""
    mask = (1 << (width_bytes * 8)) - 1
    return format(value & mask, f"0{width_bytes * 2}X").encode("ascii")


def _dec_ascii(data: bytes) -> int:
    return int(data.decode("ascii"), 16)


def _try_hex(data: bytes) -> int | None:
    """ASCII hex 解码; 非 hex/非 ASCII 返回 None (校验清单转失败项, 不抛)。"""
    try:
        return _dec_ascii(data)
    except ValueError:  # 含 UnicodeDecodeError
        return None


def header_len(frame_format: str = FRAME_3E_BINARY) -> int:
    return _HEADER_LENS[frame_format]


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


def _subheader_bytes(fmt: str, resp: bool) -> bytes:
    if _is_ascii(fmt):
        return _enc_ascii(_RESP_SUBHEADERS[fmt] if resp else _REQ_SUBHEADERS[fmt], 2)
    return struct.pack(">H", _RESP_SUBHEADERS[fmt] if resp else _REQ_SUBHEADERS[fmt])


def _route_bytes(fmt: str, network: int, pc: int, module_io: int, module_station: int) -> bytes:
    """路由 5B: 网络1 + PC1 + I/O2(小端) + 站号1。ASCII 同字段按 hex 字符。"""
    if _is_ascii(fmt):
        return _enc_ascii(network, 1) + _enc_ascii(pc, 1) + _enc_ascii(module_io, 2) + _enc_ascii(module_station, 1)
    return bytes([network, pc]) + struct.pack("<H", module_io) + bytes([module_station])


def _header_fmt(
    frame_format: str,
    network: int,
    pc: int,
    module_io: int,
    module_station: int,
    timer: int,
    data_len: int,
    serial: int = 0,
) -> bytes:
    """请求帧头 (标准顺序): 副头部 + 路由5B + 数据长2B + 定时器2B。"""
    out = _subheader_bytes(frame_format, resp=False)
    if _is_4e(frame_format):
        if _is_ascii(frame_format):
            out += _enc_ascii(serial, 2) + _enc_ascii(0, 2)
        else:
            out += struct.pack("<HH", serial, 0)
    out += _route_bytes(frame_format, network, pc, module_io, module_station)
    if _is_ascii(frame_format):
        out += _enc_ascii(data_len, 2) + _enc_ascii(timer, 2)
    else:
        out += struct.pack("<HH", data_len, timer)
    return out


def _parse_header_fmt(frame: bytes, frame_format: str) -> tuple:
    """请求帧头解析, 返回 (subheader, network, pc, io, station, timer, data_len, serial)。"""
    hl = _HEADER_LENS[frame_format]
    if len(frame) < hl:
        raise ValueError(f"frame too short for {frame_format} header: {len(frame)} < {hl}")
    if _is_ascii(frame_format):
        sub = _dec_ascii(frame[0:4])
        idx = 4
        serial = 0
        if _is_4e(frame_format):
            serial = _dec_ascii(frame[idx : idx + 4])
            idx += 4
            idx += 4  # 保留 2B
        network = _dec_ascii(frame[idx : idx + 2])
        idx += 2
        pc = _dec_ascii(frame[idx : idx + 2])
        idx += 2
        io = _dec_ascii(frame[idx : idx + 4])
        idx += 4
        station = _dec_ascii(frame[idx : idx + 2])
        idx += 2
        data_len = _dec_ascii(frame[idx : idx + 4])
        idx += 4
        timer = _dec_ascii(frame[idx : idx + 4])
        return sub, network, pc, io, station, timer, data_len, serial
    (sub,) = struct.unpack_from(">H", frame, 0)
    idx = 2
    serial = 0
    if _is_4e(frame_format):
        (serial,) = struct.unpack_from("<H", frame, idx)
        idx += 2
        idx += 2  # 保留 2B
    network, pc = frame[idx], frame[idx + 1]
    idx += 2
    (io,) = struct.unpack_from("<H", frame, idx)
    idx += 2
    station = frame[idx]
    idx += 1
    (data_len,) = struct.unpack_from("<H", frame, idx)
    idx += 2
    (timer,) = struct.unpack_from("<H", frame, idx)
    return sub, network, pc, io, station, timer, data_len, serial



def _tail_bytes(frame: bytes, frame_format: str) -> int:
    """数据长字段之后至帧尾的长度 (binary 按字节, ASCII 按字符, 与 pymcprotocol 一致)。"""
    n = len(frame) - _DATALEN_OFFSETS[frame_format] - (4 if _is_ascii(frame_format) else 2)
    return n


# ---------------------------------------------------------------- build

def _encode_pdu(fmt: str, cmd: int, subcmd: int, code: int, head: int, count: int) -> bytes:
    """软元件项: 命令2 + 子命令2 + 软元件号3 + 软元件代码1 + 点数2。"""
    if _is_ascii(fmt):
        name = DEVICE_CODE_NAMES.get(code)
        if name is None:
            raise ValueError(f"unknown device code {code:#04x}")
        code_str = ASCII_DEVICE_CODES[name]
        # ASCII 模式: 软元件代码(2字符)在前, 软元件号(6字符)在后 (与二进制相反)
        base = ASCII_DEVICE_BASES.get(DEVICE_CODE_NAMES.get(code, ""), 10)
        num = format(head, f"0{6}{'X' if base == 16 else 'd'}").encode("ascii")
        return (
            _enc_ascii(cmd, 2) + _enc_ascii(subcmd, 2)
            + code_str.encode("ascii") + num + _enc_ascii(count, 2)
        )
    return (
        struct.pack("<HH", cmd, subcmd)
        + struct.pack("<I", head)[:3] + bytes([code]) + struct.pack("<H", count)
    )


def _decode_pdu(fmt: str, data: bytes) -> tuple[int, int, int, int, int]:
    if _is_ascii(fmt):
        cmd = _dec_ascii(data[0:4])
        subcmd = _dec_ascii(data[4:8])
        code_str = data[8:10].decode("ascii")
        name = ASCII_DEVICE_CODE_NAMES.get(code_str, "")
        code = DEVICE_CODES.get(name, -1)
        base = ASCII_DEVICE_BASES.get(name, 10)
        head = int(data[10:16].decode("ascii"), base)
        count = _dec_ascii(data[16:20])
        return cmd, subcmd, code, head, count
    cmd, subcmd = struct.unpack_from("<HH", data, 0)
    head = int.from_bytes(data[4:7], "little")
    code = data[7]
    count = int.from_bytes(data[8:10], "little")
    return cmd, subcmd, code, head, count


def _encode_word_values(fmt: str, values: list[int]) -> bytes:
    if _is_ascii(fmt):
        return b"".join(_enc_ascii(v, 2) for v in values)
    return b"".join(struct.pack("<H", v) for v in values)


def _decode_word_values(fmt: str, raw: bytes) -> list[int]:
    if _is_ascii(fmt):
        return [_dec_ascii(raw[i : i + 4]) for i in range(0, len(raw) - 3, 4)]
    return [int.from_bytes(raw[i : i + 2], "little") for i in range(0, len(raw) - 1, 2)]


def _encode_end_code(fmt: str, code: int) -> bytes:
    return _enc_ascii(code, 2) if _is_ascii(fmt) else struct.pack("<H", code)


def _decode_end_code(fmt: str, raw: bytes) -> int:
    return _dec_ascii(raw[0:4]) if _is_ascii(fmt) else struct.unpack_from("<H", raw, 0)[0]


def _pdu_ascii_len(fmt: str) -> int:
    """软元件项编码后的字符/字节长度。"""
    if _is_ascii(fmt):
        return 20  # 4+4+6+2+4 = 20 chars
    return 10  # 2+2+3+1+2 = 10 bytes


def build_read_request(
    device: str,
    head_device: int,
    device_count: int,
    network: int = 0,
    pc: int = 0xFF,
    module_io: int = 0x03FF,
    module_station: int = 0,
    timer: int = 4,
    subcommand: int = SUBCOMMAND_WORD_UNITS,
    frame_format: str = FRAME_3E_BINARY,
    serial: int = 0,
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
    data = _encode_pdu(frame_format, CMD_BATCH_READ_WORD, subcommand, code, head_device, device_count)
    # 请求数据长度: binary 按字节 (定时器2B+数据), ascii 按字符 (定时器4字符+数据)
    data_len = (4 if _is_ascii(frame_format) else 2) + len(data)
    return _header_fmt(frame_format, network, pc, module_io, module_station, timer, data_len, serial) + data


def build_write_request(
    device: str,
    head_device: int,
    values: list[int],
    network: int = 0,
    pc: int = 0xFF,
    module_io: int = 0x03FF,
    module_station: int = 0,
    timer: int = 4,
    subcommand: int = SUBCOMMAND_WORD_UNITS,
    frame_format: str = FRAME_3E_BINARY,
    serial: int = 0,
) -> bytes:
    """构造 1401 批量写(字单位)请求帧。

    字软元件 (D/R/W): 每值一字 (0-65535, 负数按 16 位补码)。
    位软元件 (X/Y/B/M): 每值一字的 16 个点打包 (与 0401 读的打包语义一致)。
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
    if not values:
        raise ValueError("values must not be empty")
    if len(values) > MAX_READ_POINTS:
        raise ValueError(f"too many values: {len(values)} > {MAX_READ_POINTS}")
    for i, v in enumerate(values):
        if not -0x8000 <= v <= 0xFFFF:
            raise ValueError(f"values[{i}] {v} out of 16-bit word range (-32768..65535)")
    code = DEVICE_CODES[device]
    words = [v & 0xFFFF for v in values]
    data = _encode_pdu(frame_format, CMD_BATCH_WRITE_WORD, subcommand, code, head_device, len(words))
    data += _encode_word_values(frame_format, words)
    data_len = (4 if _is_ascii(frame_format) else 2) + len(data)
    return _header_fmt(frame_format, network, pc, module_io, module_station, timer, data_len, serial) + data


# ---------------------------------------------------------------- parse


def _cross_check_fmt(frame: bytes, request: bytes, frame_format: str) -> list[str]:
    """响应与请求的路由回显交叉核对 (串包/配置错位检测)。"""
    problems: list[str] = []
    try:
        _s, r_net, r_pc, r_io, r_st, _t, _dl, _ser = _parse_header_fmt(request, frame_format)
        sub, net, pc, io, st, _t2, _dl2, _ser2 = _parse_header_fmt(frame, frame_format)
    except ValueError as e:
        return [f"frame too short for cross check: {e}"]
    if (net, pc, io, st) != (r_net, r_pc, r_io, r_st):
        if net != r_net:
            problems.append(f"network_number mismatch: request {r_net}, response {net}")
        if pc != r_pc:
            problems.append(f"pc_number mismatch: request {r_pc}, response {pc}")
        if io != r_io:
            problems.append(f"module_io mismatch: request {r_io:#06x}, response {io:#06x}")
        if st != r_st:
            problems.append(f"module_station mismatch: request {r_st}, response {st}")
    return problems


def _header_fields_fmt(frame: bytes, fields: list[FrameField], frame_format: str) -> None:
    """头部字段逐项出证据 (二进制 3E: sub@0 net@2 pc@3 io@4 st@6 datalen@7 timer@9)。"""
    sub, net, pc, io, st, timer, data_len, serial = _parse_header_fmt(frame, frame_format)
    sub_sz = 4 if _is_ascii(frame_format) else 2
    fields.append(_field(frame, "subheader", sub, 0, sub_sz, "50 00=3E请求 / D0 00=3E响应 / 54 00=4E请求 / D4 00=4E响应"))
    if _is_4e(frame_format):
        ser_sz = 4 if _is_ascii(frame_format) else 2
        fields.append(_field(frame, "serial_number", serial, sub_sz, ser_sz))
    dl_off = _DATALEN_OFFSETS[frame_format]
    fields.append(_field(frame, "data_length", data_len, dl_off, sub_sz, "数据长字段之后至帧尾的字节数"))
    fields.append(_field(frame, "monitoring_timer", timer, _END_OFFSETS[frame_format], sub_sz, "仅请求帧; 响应帧同位置为结束代码"))


def parse_request(frame: bytes) -> ParseResult:
    """解析 3E 二进制请求帧 (兼容旧接口)。"""
    return parse_request_fmt(frame, FRAME_3E_BINARY)


def parse_request_fmt(frame: bytes, frame_format: str = FRAME_3E_BINARY) -> ParseResult:
    """格式化请求帧解析 (支持全部 4 种格式)。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    hl = _HEADER_LENS[frame_format]
    try:
        sub, _net, _pc, _io, _st, _timer, data_len, _serial = _parse_header_fmt(frame, frame_format)
    except ValueError as e:
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=[str(e)])
    _header_fields_fmt(frame, fields, frame_format)
    expected_sub = _REQ_SUBHEADERS[frame_format]
    if sub != expected_sub:
        errors.append(f"subheader {sub:#06x} != {expected_sub:#06x} ({frame_format} request)")
    data = frame[hl:]
    if data_len != _tail_bytes(frame, frame_format):
        errors.append(f"data_length {data_len} != timer+data bytes {_tail_bytes(frame, frame_format)}")
    pdu_len = _pdu_ascii_len(frame_format)
    if len(data) < pdu_len:
        # 软元件块不足 (binary 10B / ascii 20 字符): 截断帧转 errors, 不越界读
        errors.append(f"request data too short for device block: {len(data)} < {pdu_len}")
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=errors)
    try:
        cmd, subcmd, code, head, count = _decode_pdu(frame_format, data)
    except ValueError as e:  # ASCII 帧软元件区含非 hex/非 ASCII 字符
        errors.append(f"device block undecodable: {e}")
        return ParseResult(protocol="melsec", direction="req", fields=fields, valid=False, errors=errors)
    fields.append(_field(frame, "command", cmd, hl, 4 if _is_ascii(frame_format) else 2))
    fields.append(_field(frame, "subcommand", subcmd, hl + (4 if _is_ascii(frame_format) else 2), 4 if _is_ascii(frame_format) else 2))
    if cmd not in (CMD_BATCH_READ_WORD, CMD_BATCH_WRITE_WORD):
        errors.append(f"unsupported command {cmd:#06x} (only 0401 batch read / 1401 batch write)")
    num_off = hl + 10 if _is_ascii(frame_format) else hl + 4
    code_off = hl + 8 if _is_ascii(frame_format) else hl + 7
    cnt_off = hl + 16 if _is_ascii(frame_format) else hl + 8
    code_sz = 2 if _is_ascii(frame_format) else 1
    fields.append(_field(frame, "head_device", head, num_off, 6 if _is_ascii(frame_format) else 3))
    fields.append(_field(frame, "device_code", code, code_off, code_sz))
    fields.append(_field(frame, "device_count", count, cnt_off, 4 if _is_ascii(frame_format) else 2))
    if code not in DEVICE_CODE_NAMES:
        errors.append(f"unknown device code {code:#04x}")
    if not 1 <= count <= MAX_READ_POINTS:
        errors.append(f"device_count {count} out of range 1-{MAX_READ_POINTS}")
    return ParseResult(protocol="melsec", direction="req", fields=fields, valid=not errors, errors=errors)


def parse_response(frame: bytes, request: bytes | None = None) -> ParseResult:
    """解析 3E 二进制响应帧 (兼容旧接口)。"""
    return parse_response_fmt(frame, request=request, frame_format=FRAME_3E_BINARY)


def parse_response_fmt(frame: bytes, request: bytes | None = None, frame_format: str = FRAME_3E_BINARY) -> ParseResult:
    """格式化响应帧解析 (支持全部 4 种格式)。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    try:
        sub, _net, _pc, _io, _st, _end, data_len, _serial = _parse_header_fmt(frame, frame_format)
    except ValueError as e:
        return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=False, errors=[str(e)])
    _header_fields_fmt(frame, fields, frame_format)
    expected_sub = _RESP_SUBHEADERS[frame_format]
    if sub != expected_sub:
        errors.append(f"subheader {sub:#06x} != {expected_sub:#06x} ({frame_format} response)")
    data = frame[_DATA_START_OFFSETS[frame_format]:]
    if data_len != _tail_bytes(frame, frame_format):
        errors.append(f"data_length {data_len} != end_code+data bytes {_tail_bytes(frame, frame_format)}")
    _sz = 4 if _is_ascii(frame_format) else 2
    if len(frame) < _END_OFFSETS[frame_format] + _sz:
        errors.append("response too short for end code")
        return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=False, errors=errors)
    end_code = _decode_end_code(frame_format, frame[_END_OFFSETS[frame_format]:])
    fields.append(_field(frame, "end_code", end_code, _END_OFFSETS[frame_format], _sz, end_code_name(end_code)))
    if request is not None:
        errors.extend(_cross_check_fmt(frame, request, frame_format))
    if end_code != 0x0000:
        if len(data) > _sz:
            errors.append(f"nonzero end code but {len(data) - _sz} trailing data bytes present")
        return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=not errors, errors=errors)
    values_raw = data
    try:
        values = _decode_word_values(frame_format, values_raw)
    except ValueError as e:  # ASCII 字值区含非 hex 字符: 截断/污染转证据
        errors.append(f"word values undecodable: {e}")
        return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=False, errors=errors)
    fields.append(
        _field(frame, "word_values", values, _DATA_START_OFFSETS[frame_format], len(values_raw),
               "16-bit 小端字值" if not _is_ascii(frame_format) else "16-bit ASCII hex 字值")
    )
    if request is not None and values:
        try:
            req = parse_request_fmt(request, frame_format)
            cnt_f = next((f.value for f in req.fields if f.name == "device_count"), None)
            dev_f = next((f.value for f in req.fields if f.name == "device_code"), None)
            if isinstance(cnt_f, int) and isinstance(dev_f, int):
                dev_name = DEVICE_CODE_NAMES.get(dev_f)
                words = (cnt_f + 15) // 16 if dev_name in BIT_DEVICES else cnt_f
                if len(values) < words:
                    errors.append(f"data short: requested {words} words, got {len(values)}")
        except Exception:  # noqa: BLE001
            pass
    return ParseResult(protocol="melsec", direction="resp", fields=fields, valid=not errors, errors=errors)

# ---------------------------------------------------------------- validate


def validate_frame(frame: bytes, direction: Literal["req", "resp"] = "resp") -> list[CheckResult]:
    """3E 二进制帧校验清单 (兼容旧接口)。"""
    return validate_frame_fmt(frame, direction, FRAME_3E_BINARY)


def validate_frame_fmt(frame: bytes, direction: str = "resp", frame_format: str = FRAME_3E_BINARY) -> list[CheckResult]:
    """格式化帧校验清单 (支持全部 4 种格式)。"""
    checks: list[CheckResult] = []
    hl = _HEADER_LENS[frame_format]
    dl_off = _DATALEN_OFFSETS[frame_format]
    checks.append(CheckResult(
        name="frame_header_complete",
        passed=len(frame) >= hl,
        detail=f"got {len(frame)} bytes, need >= {hl}",
    ))
    if len(frame) < (4 if _is_ascii(frame_format) else 2):
        return checks
    expected_sub = _REQ_SUBHEADERS[frame_format] if direction == "req" else _RESP_SUBHEADERS[frame_format]
    if _is_ascii(frame_format):
        sub = _try_hex(frame[0:4])
        sub_detail = (
            f"subheader not ASCII hex: {frame[0:4].decode('ascii', errors='replace')!r}"
            if sub is None
            else f"subheader={sub:#06x} (expect {expected_sub:#06x} for {frame_format} {direction})"
        )
    else:
        sub = struct.unpack_from(">H", frame, 0)[0]
        sub_detail = f"subheader={sub:#06x} (expect {expected_sub:#06x} for {frame_format} {direction})"
    sub_ok = sub is not None and sub == expected_sub
    checks.append(CheckResult(
        name=f"subheader_{frame_format}",
        passed=sub_ok,
        detail=sub_detail,
    ))
    checks.append(CheckResult(
        name="subheader_match",
        passed=sub_ok,
        detail=sub_detail,
    ))
    fld_sz = 4 if _is_ascii(frame_format) else 2
    if len(frame) < dl_off + fld_sz:
        return checks
    if _is_ascii(frame_format):
        dl_raw = frame[dl_off : dl_off + fld_sz]
        data_len = _try_hex(dl_raw)
        if data_len is None:
            checks.append(CheckResult(
                name="data_length_consistent", passed=False,
                detail=f"data_length not ASCII hex: {dl_raw.decode('ascii', errors='replace')!r}",
            ))
    else:
        data_len = struct.unpack_from("<H", frame, dl_off)[0]
    if data_len is not None:
        actual_tail = _tail_bytes(frame, frame_format)
        checks.append(CheckResult(
            name="data_length_consistent",
            passed=data_len == actual_tail,
            detail=f"data_length={data_len}, actual tail bytes={actual_tail}",
        ))
    end_off = _END_OFFSETS[frame_format]
    if direction == "resp" and len(frame) >= end_off + 2:
        if _is_ascii(frame_format):
            end_raw = frame[end_off:end_off + 4]
            end_code = _try_hex(end_raw)
            if end_code is None:
                checks.append(CheckResult(
                    name="end_code_known", passed=False,
                    detail=f"end_code not ASCII hex: {end_raw.decode('ascii', errors='replace')!r}",
                ))
        else:
            end_code = struct.unpack_from("<H", frame, end_off)[0]
        if end_code is not None:
            checks.append(CheckResult(
                name="end_code_known",
                passed=end_code in END_CODES,
                detail=f"end_code={end_code:#06x} ({end_code_name(end_code)})",
            ))
    if direction == "req" and len(frame) >= hl + 2:
        try:
            cmd, _subcmd, _code, _head, _count = _decode_pdu(frame_format, frame[hl:])
        except Exception:  # noqa: BLE001
            checks.append(CheckResult(name="command_supported", passed=False, detail="missing command"))
        else:
            checks.append(CheckResult(
                name="command_supported",
                passed=cmd == CMD_BATCH_READ_WORD,
                detail=f"command={cmd:#06x} (0x0401 = batch read word units)",
            ))
    return checks



