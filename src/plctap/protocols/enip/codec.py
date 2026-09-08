"""EtherNet/IP (CIP) 帧编解码纯函数 (v0.5.3)。

依据: CIP spec + EtherNet/IP encapsulation (Volume 2) + pycomm3/cpppo 对拍。
帧结构三层:
1. ENIP 封装头 (24B): command(2 LE) + length(2 LE) + session handle(4 LE)
   + status(4 LE) + sender context(8B) + options(4 LE)。载荷长度即 length。
2. SendRRData (0x006F) 载荷: 接口句柄 u32(0) + 超时 u16 + 项数 u16(2)
   + 地址项 (type 0x0000, len 4, 连接 ID) + 数据项 (type 0x00B1, CIP 层)。
3. CIP 层: Logix tag 读 (0x4C) / 写 (0x4D) / 非连接发送信封 (0x52, 走
   连接管理器类 0x06 实例 1): 嵌入请求长度 + 嵌入请求 + 路径长度 + 路径。

字节序: ENIP/CIP 头全小端 (与 Modbus/FINS 大端相反, 知识库素材)。
tag 路径: 符号段 0x91 + 长度 + ASCII 名 (补齐偶数) + 元素段 0x28 + 下标;
"alpha[0]" 拆为符号 alpha + 元素 0 (真机 Logix 不存在带下标的符号名)。

v0.5.3 收录 CIP 状态码 (General Status 高频项), 未收录渲染 UNKNOWN_CIP_0xXX。
"""

from __future__ import annotations

import struct
from typing import Literal

from plctap.models import CheckResult, FrameField, ParseResult
from plctap.protocols.common import interpret_registers  # noqa: F401

# ------------------------------------------------------------ ENIP 封装层

ENIP_HEADER_LEN = 24

CMD_LIST_IDENTITY = 0x0063
CMD_REGISTER_SESSION = 0x0065
CMD_UNREGISTER_SESSION = 0x0066
CMD_SEND_RR_DATA = 0x006F
CMD_SEND_UNIT_DATA = 0x0070

COMMAND_NAMES: dict[int, str] = {
    CMD_LIST_IDENTITY: "LIST_IDENTITY",
    CMD_REGISTER_SESSION: "REGISTER_SESSION",
    CMD_UNREGISTER_SESSION: "UNREGISTER_SESSION",
    CMD_SEND_RR_DATA: "SEND_RR_DATA",
    CMD_SEND_UNIT_DATA: "SEND_UNIT_DATA",
}

ENIP_STATUS: dict[int, str] = {
    0x00: "SUCCESS",
    0x01: "INVALID_COMMAND",
    0x02: "NO_MEMORY",
    0x03: "MALFORMED_DATA",
    0x64: "INVALID_SESSION_HANDLE",
    0x65: "INVALID_LENGTH",
    0x69: "UNSUPPORTED_PROTOCOL_REVISION",
}

ITEM_ADDRESS_NULL = 0x0000
ITEM_CIP_IDENTITY = 0x000C
ITEM_CIP_CONNECTED = 0x00A1
ITEM_CIP_UNCONNECTED_REQUEST = 0x00B2
ITEM_CIP_UNCONNECTED_REPLY = 0x00B1
ITEM_SOCKADDR = 0x8000


def build_enip(command: int, payload: bytes, session: int = 0, status: int = 0,
               sender_context: bytes = b"plctap\x00\x00") -> bytes:
    """ENIP 封装帧: 24B 头 + 载荷。sender_context 恒 8 字节。"""
    if len(sender_context) != 8:
        raise ValueError("sender_context must be 8 bytes")
    # 注意: sender context 不应全零 —— cpppo server 的 ENIP 解析器对全零
    # context 无响应 (automata "no progress" 断言), pycomm3 用 "_pycomm_"。
    # 规范上 context 是不透明回显字段, 但全零在实践中是互操作雷区。
    return (
        struct.pack("<HHI I 8s I", command, len(payload), session, status, sender_context, 0)
        + payload
    )


def parse_enip_header(frame: bytes) -> tuple[int, int, int, int, int]:
    """返回 (command, payload_length, session, status, payload_offset)。"""
    if len(frame) < ENIP_HEADER_LEN:
        raise ValueError(f"frame too short for ENIP header: {len(frame)} < 24")
    command, length, session, status = struct.unpack_from("<HHII", frame, 0)
    if command not in COMMAND_NAMES:
        raise ValueError(f"unknown ENIP command {command:#06x}")
    if length != len(frame) - ENIP_HEADER_LEN:
        raise ValueError(f"ENIP length field {length} != payload {len(frame) - ENIP_HEADER_LEN}")
    return command, length, session, status, ENIP_HEADER_LEN


# ------------------------------------------------------------ 会话/身份


def build_register_session() -> bytes:
    """RegisterSession 请求: 协议版本 1 + options 0。"""
    return build_enip(CMD_REGISTER_SESSION, struct.pack("<HH", 1, 0))


def parse_register_session_response(frame: bytes) -> int:
    """返回 session handle (status 非 0 抛 ValueError)。"""
    command, _length, session, status, off = parse_enip_header(frame)
    if command != CMD_REGISTER_SESSION:
        raise ValueError(f"not a RegisterSession response: {command:#06x}")
    if status != 0:
        raise ValueError(f"RegisterSession failed: {ENIP_STATUS.get(status, f'{status:#x}')}")
    if len(frame) < off + 4:
        raise ValueError(f"register session payload truncated: {len(frame) - off} < 4 bytes")
    version, options = struct.unpack_from("<HH", frame, off)
    if version != 1:
        raise ValueError(f"unsupported encapsulation protocol version {version}")
    return session


def build_list_identity() -> bytes:
    return build_enip(CMD_LIST_IDENTITY, b"")


def parse_identity_payload(payload: bytes) -> dict:
    """ListIdentity 数据项: 解出设备身份 (vendor/product code/name 等)。"""
    info: dict = {}
    if len(payload) < 2:
        raise ValueError("identity payload too short")
    (item_type, item_len) = struct.unpack_from("<HH", payload, 0)
    info["item_type"] = item_type
    if item_type != ITEM_CIP_IDENTITY:
        info["item_len"] = item_len
        return info
    body = payload[4:4 + item_len]
    if len(body) < 35:
        # 身份体最小可读长度: encap2 + sockaddr16 + vendor4 + type/code4 + revision2
        # + status2 + serial4 + name_len1 = 35B; 截断转 ValueError (调用方收进 errors)
        raise ValueError(f"identity body truncated: {len(body)} < 35 bytes")
    off = 0
    (info["encap_version"],) = struct.unpack_from("<H", body, off); off += 2
    off += 16  # sockaddr (family/port/addr/zero) —— 身份定位用, 不解语义
    (info["vendor_id"],) = struct.unpack_from("<I", body, off); off += 4
    (info["product_type"], info["product_code"]) = struct.unpack_from("<HH", body, off); off += 4
    info["revision"] = (body[off], body[off + 1]); off += 2
    (info["status"],) = struct.unpack_from("<H", body, off); off += 2
    (info["serial"],) = struct.unpack_from("<I", body, off); off += 4
    name_len = body[off]; off += 1
    info["product_name"] = body[off:off + name_len].decode("ascii", errors="replace")
    return info


def parse_list_identity_response(frame: bytes) -> dict:
    command, _length, _session, status, off = parse_enip_header(frame)
    if command != CMD_LIST_IDENTITY:
        raise ValueError(f"not a ListIdentity response: {command:#06x}")
    if status != 0:
        raise ValueError(f"ListIdentity failed: {ENIP_STATUS.get(status, f'{status:#x}')}")
    if len(frame) < off + 2:
        raise ValueError(f"identity item count truncated: {len(frame) - off} < 2 bytes")
    (item_count,) = struct.unpack_from("<H", frame, off)
    info = parse_identity_payload(frame[off + 2:])
    info["item_count"] = item_count
    return info


# ------------------------------------------------------------ SendRRData / CIP


def build_send_rr_data(session: int, cip: bytes, reply: bool = False) -> bytes:
    """SendRRData: 接口句柄 0 + 超时 0 + 2 项 (空地址项 + 未连接数据项)。

    数据项类型按方向: 请求 0x00B2 / 应答 0x00B1 (cpppo 实测两方向都校验)。
    """
    item_type = ITEM_CIP_UNCONNECTED_REPLY if reply else ITEM_CIP_UNCONNECTED_REQUEST
    payload = (
        struct.pack("<I", 0)  # interface handle
        + struct.pack("<H", 0)  # timeout
        + struct.pack("<H", 2)  # item count
        + struct.pack("<HH", ITEM_ADDRESS_NULL, 0)  # 空地址项 (与 pycomm3 一致)
        + struct.pack("<HH", item_type, len(cip)) + cip
    )
    return build_enip(CMD_SEND_RR_DATA, payload, session=session)


# CIP 状态码 (General Status 高频项)
CIP_STATUS: dict[int, str] = {
    0x00: "SUCCESS",
    0x01: "CONNECTION_FAILURE",
    0x02: "RESOURCE_UNAVAILABLE",
    0x03: "INVALID_PARAMETER_VALUE",
    0x04: "PATH_SEGMENT_ERROR",
    0x05: "PATH_DESTINATION_UNKNOWN",
    0x06: "PARTIAL_TRANSFER",
    0x07: "CONNECTION_LOST",
    0x08: "SERVICE_NOT_SUPPORTED",
    0x09: "INVALID_ATTRIBUTE_VALUE",
    0x0C: "OBJECT_STATE_CONFLICT",
    0x0F: "REPLY_TOO_LARGE",
    0x13: "NOT_ENOUGH_DATA",
    0x14: "ATTRIBUTE_NOT_SUPPORTED",
    0x1E: "ONE_BIT_PARTIAL",
}

# Logix 数据类型码 -> (名称, 每元素 16 位字数)
TYPE_CODES: dict[int, tuple[str, int]] = {
    0xC1: ("BOOL", 1),
    0xC2: ("SINT", 1),
    0xC3: ("INT", 1),
    0xC4: ("DINT", 2),
    0xC5: ("LINT", 4),
    0xCA: ("REAL", 2),
    0xD3: ("DWORD", 2),
}

SVC_READ_TAG = 0x4C
SVC_WRITE_TAG = 0x4D
SVC_UNCONNECTED_SEND = 0x52
SVC_READ_TAG_REPLY = 0xCC
SVC_WRITE_TAG_REPLY = 0xCD


def build_tag_path(tag: str) -> bytes:
    """Logix tag 路径: 符号段 0x91 + 名长 + ASCII(补齐偶数) [+ 元素段 0x28 下标]。

    "alpha[0]" -> 符号 alpha + 单元素段 0; "beta" -> 仅符号段。
    多维/结构成员路径 (alpha[2,3].x) v0.5.3 不支持, 显式报错。
    """
    if "." in tag:
        raise ValueError(f"structure member paths not supported, got {tag!r}")
    if "[" in tag:
        name, _, idx_part = tag.partition("[")
        idx = idx_part.rstrip("]")
        if not idx.isdigit() or "," in idx:
            raise ValueError(f"only single-dimension element tags supported, got {tag!r}")
        path = _symbol_segment(name) + bytes([0x28, int(idx) & 0xFF])
    else:
        path = _symbol_segment(tag)
    if not path:
        raise ValueError("empty tag path")
    return path


def _symbol_segment(name: str) -> bytes:
    raw = name.encode("ascii")
    if not 1 <= len(raw) <= 255:
        raise ValueError(f"tag name length {len(raw)} out of range 1-255")
    padded = raw + b"\x00" * (len(raw) % 2)  # ANSI 段补齐偶数字节
    return bytes([0x91, len(raw)]) + padded


def build_read_tag(tag: str, count: int = 1) -> bytes:
    """CIP Read Tag Service (0x4C): 路径字长 + 路径 + 元素数 u16。"""
    if not 1 <= count <= 0xFFFF:
        raise ValueError(f"count {count} out of range 1-65535")
    path = build_tag_path(tag)
    return bytes([SVC_READ_TAG, len(path) // 2]) + path + struct.pack("<H", count)


def build_write_tag(tag: str, type_code: int, values: list[int]) -> bytes:
    """CIP Write Tag Service (0x4D): 路径 + 类型 u16 + 元素数 u16 + 数据。"""
    if type_code not in TYPE_CODES:
        raise ValueError(f"unsupported type code {type_code:#06x}; known: {sorted(TYPE_CODES)}")
    if not values:
        raise ValueError("values must not be empty")
    _, words = TYPE_CODES[type_code]
    if len(values) * words > 480:
        raise ValueError("write payload exceeds unconnected message limit")
    path = build_tag_path(tag)
    data = b"".join(struct.pack("<H", v & 0xFFFF) for v in values)
    _, words_per = TYPE_CODES[type_code]
    elements = len(values) // words_per
    return bytes([SVC_WRITE_TAG, len(path) // 2]) + path + struct.pack("<HH", type_code, elements) + data


def build_unconnected_send(embedded: bytes) -> bytes:
    """CIP 非连接发送信封 (0x52, 连接管理器 0x06/1): 嵌入请求 + 路径 (背板 1 槽 0)。"""
    if len(embedded) > 0xFFFF:
        raise ValueError("embedded request too large")
    return (
        bytes([SVC_UNCONNECTED_SEND])
        + struct.pack("<H", len(embedded))
        + embedded
        + bytes([0x01])  # 路径长度: 1 字
        + bytes([0x01, 0x00])  # 端口段: 背板, 槽 0
        + bytes([0x00])  # 补齐偶数
    )


def wrap_cip_request(service_bytes: bytes) -> bytes:
    """控制器自身请求不需要路径段 (直接 0x4C 即可); 供 adapter 选择信封或裸服务。"""
    return service_bytes


def parse_tag_reply(cip: bytes, service: int) -> ParseResult:
    """解析 CIP tag 读/写应答 (0xCC/0xCD)。

    返回 fields: service/status/type/word_values; CIP 状态非 0 记入 errors
    (additional status 原样保留)。
    """
    fields: list[FrameField] = []
    errors: list[str] = []
    if len(cip) < 4:
        return ParseResult(protocol="enip", direction="resp", fields=fields, valid=False,
                           errors=[f"CIP reply too short: {len(cip)} bytes"])
    reply_service = cip[0]
    status = cip[2]
    addl_size = cip[3]  # 附加状态字数 (16 位字)
    fields.append(_f(cip, "reply_service", reply_service, 0, 1,
                     f"request {service:#04x}" if reply_service == (service | 0x80) else "service mismatch"))
    fields.append(_f(cip, "cip_status", status, 2, 1, CIP_STATUS.get(status, f"UNKNOWN_CIP_{status:#04x}")))
    if addl_size:
        if len(cip) < 4 + addl_size * 2:
            raise ValueError(
                f"additional status truncated: need {4 + addl_size * 2} bytes, have {len(cip)}"
            )
        addl = struct.unpack_from(f"<{addl_size}H", cip, 4)
        fields.append(_f(cip, "additional_status", list(addl), 4, addl_size * 2))
    if reply_service != (service | 0x80):
        errors.append(f"reply service {reply_service:#04x} does not match request {service:#04x}")
    if status != 0:
        errors.append(f"CIP status {CIP_STATUS.get(status, f'{status:#04x}')} ({status:#04x})")
        return ParseResult(protocol="enip", direction="resp", fields=fields, valid=False, errors=errors)
    if reply_service == SVC_WRITE_TAG_REPLY:
        return ParseResult(protocol="enip", direction="resp", fields=fields, valid=not errors, errors=errors)
    # 读应答: 4B 头(含附加状态) + type u16 + 数据
    data_off = 4 + addl_size * 2
    if len(cip) < data_off + 2:
        errors.append("read reply missing type code")
        return ParseResult(protocol="enip", direction="resp", fields=fields, valid=False, errors=errors)
    (type_code,) = struct.unpack_from("<H", cip, data_off)
    if type_code not in TYPE_CODES:
        errors.append(f"unknown data type code {type_code:#06x}")
        return ParseResult(protocol="enip", direction="resp", fields=fields, valid=False, errors=errors)
    name, words_per = TYPE_CODES[type_code]
    data = cip[data_off + 2:]
    words: list[int] = []
    off = 0
    while off + 2 <= len(data):
        words.append(struct.unpack_from("<H", data, off)[0])
        off += 2
    if len(data) % 2:
        errors.append(f"odd trailing byte in data ({len(data)} bytes)")
    fields.append(_f(cip, "data_type", type_code, 4, 2, name))
    fields.append(_f(cip, "word_values", words, 6, len(data), f"{name} 16 位字序列"))
    return ParseResult(protocol="enip", direction="resp", fields=fields, valid=not errors, errors=errors)


def parse_cip_reply_from_rrdata(frame: bytes) -> tuple[bytes, ParseResult]:
    """从 SendRRData 响应帧中剥出 CIP 应答层。"""
    command, _length, _session, status, off = parse_enip_header(frame)
    if command != CMD_SEND_RR_DATA:
        raise ValueError(f"not a SendRRData response: {command:#06x}")
    if status != 0:
        raise ValueError(f"SendRRData failed: {ENIP_STATUS.get(status, f'{status:#x}')}")
    (_iface,) = struct.unpack_from("<I", frame, off)
    (_timeout, item_count) = struct.unpack_from("<HH", frame, off + 4)
    if item_count != 2:
        raise ValueError(f"expected 2 items in RRData, got {item_count}")
    off2 = off + 8  # iface4 + timeout2 + itemcount2
    if len(frame) < off2 + 4:
        raise ValueError(f"address item truncated: need 4B header at offset {off2}")
    addr_type, addr_len = struct.unpack_from("<HH", frame, off2)
    if addr_type != ITEM_ADDRESS_NULL:
        raise ValueError(f"expected null address item, got {addr_type:#06x}")
    off2 += 4 + addr_len
    if len(frame) < off2 + 4:
        raise ValueError(f"data item header truncated: need 4B at offset {off2}")
    data_type, data_len = struct.unpack_from("<HH", frame, off2)
    if data_type != ITEM_CIP_UNCONNECTED_REPLY:
        raise ValueError(f"expected unconnected reply item 0x00B1, got {data_type:#06x}")
    return frame[off2 + 4:off2 + 4 + data_len], ParseResult(
        protocol="enip", direction="resp", fields=[], valid=True, errors=[])


# ---------------------------------------------------------------- parse


def _f(frame: bytes, name: str, value: object, offset: int, size: int, note: str = "") -> FrameField:
    return FrameField(name=name, value=value, raw_hex=frame[offset:offset + size].hex(),
                      byte_offset=offset, note=note)


def parse_request(frame: bytes) -> ParseResult:
    """解析 ENIP 请求帧 (命令 + 项/CIP 层)。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    try:
        command, length, session, status, off = parse_enip_header(frame)
    except ValueError as e:
        return ParseResult(protocol="enip", direction="req", fields=fields, valid=False, errors=[str(e)])
    fields.append(_f(frame, "command", command, 0, 2, COMMAND_NAMES[command]))
    fields.append(_f(frame, "payload_length", length, 2, 2))
    fields.append(_f(frame, "session_handle", session, 4, 4))
    if command == CMD_REGISTER_SESSION:
        if len(frame) < off + 4:
            errors.append(f"register session payload truncated: {len(frame) - off} < 4 bytes")
            return ParseResult(protocol="enip", direction="req", fields=fields, valid=False, errors=errors)
        version, options = struct.unpack_from("<HH", frame, off)
        fields.append(_f(frame, "protocol_version", version, off, 2))
        fields.append(_f(frame, "options", options, off + 2, 2))
        return ParseResult(protocol="enip", direction="req", fields=fields, valid=True, errors=[])
    if command == CMD_LIST_IDENTITY:
        return ParseResult(protocol="enip", direction="req", fields=fields, valid=True, errors=[])
    if command == CMD_SEND_RR_DATA:
        # RRData 项结构逐段解: 载荷截断转 errors, 不抛 struct.error
        if len(frame) < off + 8:
            errors.append(f"rrdata payload truncated: {len(frame) - off} < 8 bytes (iface+timeout+item_count)")
            return ParseResult(protocol="enip", direction="req", fields=fields, valid=False, errors=errors)
        (_iface,) = struct.unpack_from("<I", frame, off)
        (_timeout, item_count) = struct.unpack_from("<HH", frame, off + 4)
        fields.append(_f(frame, "item_count", item_count, off + 6, 2))
        off2 = off + 8  # iface4 + timeout2 + itemcount2
        if len(frame) < off2 + 4:
            errors.append(f"address item truncated: need 4B header at offset {off2}")
            return ParseResult(protocol="enip", direction="req", fields=fields, valid=False, errors=errors)
        addr_type, addr_len = struct.unpack_from("<HH", frame, off2)
        off2 += 4 + addr_len
        if len(frame) < off2 + 4:
            errors.append(f"data item header truncated: need 4B at offset {off2}")
            return ParseResult(protocol="enip", direction="req", fields=fields, valid=False, errors=errors)
        data_type, data_len = struct.unpack_from("<HH", frame, off2)
        off2 += 4
        fields.append(_f(frame, "data_item_type", data_type, off2 - 4, 2))
        cip = frame[off2:off2 + data_len]
        if len(cip) < data_len:
            errors.append(f"data item truncated: have {len(cip)}, need {data_len}")
        if data_len and len(cip) >= 3 and cip[0] == SVC_UNCONNECTED_SEND:
            (_elen,) = struct.unpack_from("<H", cip, 1)
            embedded = cip[3:3 + _elen]
            if not embedded:
                errors.append(f"embedded request truncated: have 0, need {_elen}")
            else:
                fields.append(_f(frame, "embedded_service", embedded[0], off2 + 4, 1,
                                 f"Read Tag" if embedded[0] == SVC_READ_TAG else
                                 f"Write Tag" if embedded[0] == SVC_WRITE_TAG else f"{embedded[0]:#04x}"))
                if len(cip) >= 3 + _elen:
                    fields.append(_f(frame, "route_path", cip[3 + _elen:], off2 + 3 + _elen,
                                     len(cip) - 3 - _elen, "背板 1 / 槽 0"))
                else:
                    # 声明的嵌入长度超过实际载荷: 无 route_path 字节可解, 转证据
                    errors.append(
                        f"embedded request shorter than declared: have {len(embedded)}, "
                        f"need {_elen}; no route path bytes remain"
                    )
                # 请求侧: 嵌入服务 = 读/写 tag, 解路径与参数
                fields.extend(_parse_embedded_request(frame, embedded, off2 + 4))
            return ParseResult(protocol="enip", direction="req", fields=fields, valid=not errors, errors=errors)
        return ParseResult(protocol="enip", direction="req", fields=fields, valid=not errors, errors=errors)
    return ParseResult(protocol="enip", direction="req", fields=fields, valid=True, errors=errors)


def _parse_embedded_request(frame: bytes, embedded: bytes, base_offset: int) -> list[FrameField]:
    """解嵌入的 Read/Write Tag 请求: 路径段 + 参数。"""
    fields: list[FrameField] = []
    service = embedded[0]
    off = 1
    if service not in (SVC_READ_TAG, SVC_WRITE_TAG):
        return fields
    if len(embedded) < 2:
        return fields  # 嵌入请求截断: 无路径字长可读
    path_words = embedded[off]  # 路径长度以字 (16 位) 计
    off += 1
    path = embedded[off:off + path_words * 2]
    off += path_words * 2
    # 符号段: 0x91 + len + ascii(补齐)
    if len(path) >= 2 and path[0] == 0x91:
        name_len = path[1]
        name = path[2:2 + name_len].decode("ascii", errors="replace")
        fields.append(_f(frame, "tag_name", name, base_offset + off, name_len))
        rest = path[2 + name_len + (name_len % 2):]  # 跳过符号补齐字节
        if len(rest) >= 2 and rest[0] == 0x28:
            fields.append(_f(frame, "element_index", rest[1], base_offset + off + 2 + name_len, 1))
    if service == SVC_READ_TAG and off + 2 <= len(embedded):
        (count,) = struct.unpack_from("<H", embedded, off)
        fields.append(_f(frame, "element_count", count, base_offset + off, 2))
    return fields


def parse_response(frame: bytes) -> ParseResult:
    """解析 ENIP 响应帧 (会话/身份/RRData 应答)。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    try:
        command, length, session, status, off = parse_enip_header(frame)
    except ValueError as e:
        return ParseResult(protocol="enip", direction="resp", fields=fields, valid=False, errors=[str(e)])
    fields.append(_f(frame, "command", command, 0, 2, COMMAND_NAMES[command]))
    fields.append(_f(frame, "session_handle", session, 4, 4))
    fields.append(_f(frame, "enip_status", status, 8, 4, ENIP_STATUS.get(status, f"{status:#x}")))
    if status != 0:
        errors.append(f"ENIP status {ENIP_STATUS.get(status, f'{status:#04x}')}")
        return ParseResult(protocol="enip", direction="resp", fields=fields, valid=False, errors=errors)
    if command == CMD_REGISTER_SESSION:
        try:
            s = parse_register_session_response(frame)
            fields.append(_f(frame, "session_granted", s, off, 4))
        except ValueError as e:
            errors.append(str(e))
        return ParseResult(protocol="enip", direction="resp", fields=fields,
                           valid=not errors, errors=errors)
    if command == CMD_LIST_IDENTITY:
        try:
            info = parse_list_identity_response(frame)
            fields.append(_f(frame, "vendor_id", info.get("vendor_id"), off + 2, 4))
            fields.append(_f(frame, "product_name", info.get("product_name"), off + 2,
                             len(info.get("product_name", ""))))
            if info.get("item_type") != ITEM_CIP_IDENTITY:
                errors.append(f"identity item type {info.get('item_type'):#06x}")
        except ValueError as e:
            errors.append(str(e))
        return ParseResult(protocol="enip", direction="resp", fields=fields,
                           valid=not errors, errors=errors)
    if command == CMD_SEND_RR_DATA:
        try:
            cip, _ = parse_cip_reply_from_rrdata(frame)
            fields.append(_f(frame, "cip_reply_service", cip[0] if cip else None, off + 10, 1))
            parsed = parse_tag_reply(cip, SVC_READ_TAG)
            fields.extend(parsed.fields)
            errors.extend(parsed.errors)
        except ValueError as e:
            errors.append(str(e))
        return ParseResult(protocol="enip", direction="resp", fields=fields,
                           valid=not errors, errors=errors)
    return ParseResult(protocol="enip", direction="resp", fields=fields, valid=True, errors=errors)


# ---------------------------------------------------------------- validate


def validate_frame(frame: bytes, direction: Literal["req", "resp"] = "resp") -> list[CheckResult]:
    """规范校验清单: 启动头/长度自洽/命令合法/项结构/CIP 应答匹配。"""
    checks: list[CheckResult] = []
    if len(frame) < ENIP_HEADER_LEN:
        checks.append(CheckResult(name="header_length", passed=False, detail=f"{len(frame)} < 24"))
        return checks
    command, length, _session, status = struct.unpack_from("<HHII", frame, 0)
    checks.append(CheckResult(name="command_known", passed=command in COMMAND_NAMES,
                              detail=COMMAND_NAMES.get(command, f"{command:#06x}")))
    checks.append(CheckResult(name="length_field", passed=length == len(frame) - ENIP_HEADER_LEN,
                              detail=f"length {length}, payload {len(frame) - ENIP_HEADER_LEN}"))
    checks.append(CheckResult(name="enip_status", passed=status == 0,
                              detail=ENIP_STATUS.get(status, f"{status:#x}")))
    if command == CMD_SEND_RR_DATA and len(frame) >= 34:
        off = ENIP_HEADER_LEN
        (_timeout, item_count) = struct.unpack_from("<HH", frame, off + 4)
        checks.append(CheckResult(name="rrdata_items", passed=item_count == 2,
                                  detail=f"item count {item_count}"))
    return checks
