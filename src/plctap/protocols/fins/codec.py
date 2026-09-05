"""Omron FINS/TCP 帧编解码纯函数 (M2)。

依据: Omron FINS/TCP Command Manual (W463) + FINS Command Reference (W380)。
帧结构两层, 解析时都要覆盖:
1. TCP 层: "FINS" magic(4B) + length(4B BE, = 其后字节数) + command(4B BE)
   + error(4B BE) + payload。命令 0x00 节点连接请求 / 0x01 节点连接确认 /
   0x02 FINS 帧发送 (生态主流; 0x04 为部分实现变体, 解析两者等价)。
2. FINS 层: ICF/RSV/GCT + 目标/源网络地址 5B +
   SID(1B) + 命令码(2B BE)。0101 = 存储区读; 响应带端结码(2B BE) + 数据。

字节序: FINS 全大端 (与 MC 相反, 知识库素材)。
端结码映射收录常见项 (W380 手册), 未收录的渲染 UNKNOWN_0xXXXX ——
不做臆测映射, 诊断叙述交给知识库。
"""

from __future__ import annotations

import struct
from typing import Literal

from plctap.models import CheckResult, FrameField, ParseResult
from plctap.protocols.common import interpret_registers  # noqa: F401  # 统一解释入口

TCP_MAGIC = b"FINS"
TCP_HEADER_LEN = 16  # magic4 + length4 + command4 + error4

TCP_CMD_CONNECT_REQ = 0x00000000
TCP_CMD_CONNECT_CFM = 0x00000001
# 0x02 的语义: W420/W463 "FINS frame sending" —— 主流生态值, IoTClient /
# node-omron-fins / pypi fins 均以 0x02 发 FINS 数据帧 (经真机验证);
# 拒绝连接以连接确认帧的 error 字段承载 (如 0x21 已连接), 短 payload 的
# 0x02 帧在 auto 方向判别中仍按 refused 处理。
TCP_CMD_DATA_SEND = 0x00000002
TCP_CMD_CONNECT_REFUSED = TCP_CMD_DATA_SEND  # 旧名兼容
TCP_CMD_CONNECT_STATUS = 0x00000003
# 0x04: 部分手册/实现记录的 FINS 帧交换值, 解析侧与 0x02 等价接受
TCP_CMD_EXCHANGE = 0x00000004
TCP_CMD_CLOSE = 0x00000005

TCP_COMMAND_NAMES: dict[int, str] = {
    TCP_CMD_CONNECT_REQ: "NODE_CONNECTION_REQUEST",
    TCP_CMD_CONNECT_CFM: "NODE_CONNECTION_CONFIRM",
    TCP_CMD_DATA_SEND: "FINS_FRAME_SENDING",
    TCP_CMD_EXCHANGE: "FINS_FRAME_EXCHANGE_VARIANT",
    TCP_CMD_CONNECT_STATUS: "NODE_CONNECTION_STATUS",
    TCP_CMD_CLOSE: "CONNECTION_CLOSED",
}

FINS_HEADER_LEN = 10  # ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID

# FINS 数据交换在生态中存在 0x02 (主流) 与 0x04 (变体) 两种 TCP 命令值。
# parse_request/parse_response/诊断/监听一律两者都接受;
# adapter 发送用 0x02 —— 与真实设备及主流客户端互通面最大。
FINS_EXCHANGE_COMMANDS = frozenset({TCP_CMD_EXCHANGE, TCP_CMD_DATA_SEND})

# 存储区读命令 (0101); 写 (0102) 留 M3 写闸门
CMD_MEMORY_AREA_READ = 0x0101
CMD_MEMORY_AREA_WRITE = 0x0102

# 存储区代码 (字读); 位读变体留诊断知识库, 工具只做字读
AREA_CODES: dict[str, int] = {
    "CIO": 0xB0,
    "W": 0xB1,
    "H": 0xB2,
    "A": 0xB3,
    "DM": 0x82,
    "EM": 0xA0,
}
AREA_CODE_NAMES: dict[int, str] = {v: k for k, v in AREA_CODES.items()}

END_CODES: dict[int, str] = {
    0x0000: "NORMAL_COMPLETION",
    0x0101: "SERVICE_CANCELLED",
    0x0201: "LOCAL_NODE_ERROR",
    0x0202: "REMOTE_NODE_ERROR",
    0x0203: "COMMUNICATIONS_CONTROLLER_ERROR",
    0x0204: "NOT_ABLE_TO_EXECUTE",
    0x0205: "SERVICE_REJECTED",
    0x0206: "NO_RESPONSE_FROM_REMOTE_NODE",
    0x0208: "COMMUNICATIONS_ERROR",
    0x0304: "DESTINATION_NODE_ERROR",
    0x0401: "SERVICE_UNDEFINED",
    0x0402: "SERVICE_DISABLED",
    0x0404: "BUSY",
    0x0405: "ACCESS_DENIED",
    0x1101: "ADDRESS_RANGE_ERROR",
    0x1102: "AREA_TYPE_ERROR",
}

MAX_READ_WORDS = 32766  # 0101 数据上限 (PDU 上限内取手册值, 工具层另行收窄)


def end_code_name(code: int) -> str:
    return END_CODES.get(code, f"UNKNOWN_{code:#06x}")


# ---------------------------------------------------------------- TCP 层 build


def build_tcp_frame(command: int, payload: bytes, error: int = 0) -> bytes:
    """构造 FINS/TCP 帧: length 字段 = 其后所有字节 (command+error+payload)。"""
    if not 0 <= command <= 0xFFFFFFFF:
        raise ValueError(f"tcp command {command} out of range")
    if not 0 <= error <= 0xFFFFFFFF:
        raise ValueError(f"tcp error {error} out of range")
    return (
        TCP_MAGIC
        + struct.pack(">I", 8 + len(payload))
        + struct.pack(">I", command)
        + struct.pack(">I", error)
        + payload
    )


def build_handshake_request(client_node: int) -> bytes:
    """节点连接请求 (TCP cmd 0x00): payload = 客户端节点号 (4B BE)。

    节点号 1-239 (0 忽略, 240+ 保留)。adapter 内默认用固定值,
    多实例并存的冲突场景见 adapter 注释。
    """
    if not 0 <= client_node <= 0xFF:
        raise ValueError(f"client node {client_node} out of range 0-255")
    return build_tcp_frame(TCP_CMD_CONNECT_REQ, struct.pack(">I", client_node))


def build_read_request(
    sid: int,
    client_node: int,
    area_code: int,
    address: int,
    count: int,
    dest_network: int = 0,
    dest_node: int = 0,
    dest_unit: int = 0,
) -> bytes:
    """构造 0101 存储区读请求 (完整 FINS/TCP 交换帧)。

    address 为字地址 (位地址恒 0, 位读不在 M2 范围)。
    """
    if not 0 <= sid <= 0xFF:
        raise ValueError(f"sid {sid} out of range 0-255")
    if area_code not in AREA_CODE_NAMES:
        raise ValueError(
            f"unknown area code {area_code:#04x}; known: {sorted(AREA_CODE_NAMES)}"
        )
    if not 0 <= address <= 0xFFFF:
        raise ValueError(f"address {address} out of range 0-65535")
    if not 1 <= count <= MAX_READ_WORDS:
        raise ValueError(f"count {count} out of range 1-{MAX_READ_WORDS}")
    for name, v in (("dest_network", dest_network), ("dest_node", dest_node), ("dest_unit", dest_unit)):
        if not 0 <= v <= 0xFF:
            raise ValueError(f"{name} {v} out of range 0-255")
    fins = (
        bytes([0x80, 0x00, 0x02])  # ICF=响应要求, RSV=0, GCT=2 (网关计数, 规范默认)
        + bytes([dest_network, dest_node, dest_unit])  # DNA DA1 DA2
        + bytes([0x00, client_node, 0x00])  # SNA SA1 SA2 (SA1 = 客户端节点号)
        + bytes([sid])
        + struct.pack(">H", CMD_MEMORY_AREA_READ)
        + bytes([area_code])
        + struct.pack(">HB", address, 0)  # 字地址 2B + 位地址 1B
        + struct.pack(">H", count)
    )
    return build_tcp_frame(TCP_CMD_DATA_SEND, fins)


def build_memory_area_write(
    sid: int,
    client_node: int,
    area_code: int,
    address: int,
    values: list[int],
    dest_network: int = 0,
    dest_node: int = 0,
    dest_unit: int = 0,
) -> bytes:
    """构造 0102 存储区写请求 (完整 FINS/TCP 交换帧, 字单位)。

    values 为 16 位字 (0-65535, 负数按 16 位补码), 大端上线。
    """
    if not 0 <= sid <= 0xFF:
        raise ValueError(f"sid {sid} out of range 0-255")
    if area_code not in AREA_CODE_NAMES:
        raise ValueError(
            f"unknown area code {area_code:#04x}; known: {sorted(AREA_CODE_NAMES)}"
        )
    if not 0 <= address <= 0xFFFF:
        raise ValueError(f"address {address} out of range 0-65535")
    if not values:
        raise ValueError("values must not be empty")
    if len(values) > MAX_READ_WORDS:
        raise ValueError(f"too many values: {len(values)} > {MAX_READ_WORDS}")
    for i, v in enumerate(values):
        if not -0x8000 <= v <= 0xFFFF:
            raise ValueError(f"values[{i}] {v} out of 16-bit word range (-32768..65535)")
    for name, v in (("dest_network", dest_network), ("dest_node", dest_node), ("dest_unit", dest_unit)):
        if not 0 <= v <= 0xFF:
            raise ValueError(f"{name} {v} out of range 0-255")
    words = [v & 0xFFFF for v in values]
    fins = (
        bytes([0x80, 0x00, 0x02])  # ICF=响应要求, RSV=0, GCT=2
        + bytes([dest_network, dest_node, dest_unit])  # DNA DA1 DA2
        + bytes([0x00, client_node, 0x00])  # SNA SA1 SA2
        + bytes([sid])
        + struct.pack(">H", CMD_MEMORY_AREA_WRITE)
        + bytes([area_code])
        + struct.pack(">HB", address, 0)  # 字地址 2B + 位地址 1B
        + struct.pack(">H", len(words))
        + b"".join(struct.pack(">H", w) for w in words)
    )
    return build_tcp_frame(TCP_CMD_DATA_SEND, fins)


# ---------------------------------------------------------------- TCP 层 parse


def parse_tcp_header(frame: bytes) -> tuple[int, int, bytes]:
    """解析 TCP 头, 返回 (command, error, payload)。magic/长度不符抛 ValueError。"""
    if len(frame) < TCP_HEADER_LEN:
        raise ValueError(f"frame too short for FINS/TCP header: {len(frame)} < {TCP_HEADER_LEN}")
    if frame[:4] != TCP_MAGIC:
        raise ValueError(f"bad magic {frame[:4]!r} (expected b'FINS')")
    (length,) = struct.unpack_from(">I", frame, 4)
    command, error = struct.unpack_from(">II", frame, 8)
    payload = frame[TCP_HEADER_LEN:]
    if length != 8 + len(payload):
        raise ValueError(f"tcp length field {length} != 8 + payload {len(payload)}")
    return command, error, payload


def parse_handshake_response(frame: bytes) -> dict[str, int]:
    """解析节点连接确认 (TCP cmd 0x01 或非规范的 cmd 0x00): payload = server_node(4B) + client_node(4B)。

    Omron 规范要求服务器回 cmd=1; IoTServer 等模拟器回 cmd=0, 两者都接受。
    """
    command, error, payload = parse_tcp_header(frame)
    # 部分实现 (IoTServer 等) 回 cmd=0 而非规范的 cmd=1; 只要结构自洽就接受
    if command not in (TCP_CMD_CONNECT_REQ, TCP_CMD_CONNECT_CFM):
        raise ValueError(
            f"expected connect-confirm (cmd {TCP_CMD_CONNECT_CFM}), got {command:#010x}"
            + (f" error={error:#010x}" if error else "")
        )
    if len(payload) < 8:
        raise ValueError(f"connect-confirm payload too short: {len(payload)} < 8")
    server_node, client_node = struct.unpack_from(">II", payload, 0)
    return {"server_node": server_node, "client_node": client_node, "error": error}


# ---------------------------------------------------------------- FINS 层 parse


def _field(frame: bytes, name: str, value: object, offset: int, size: int, note: str = "") -> FrameField:
    return FrameField(
        name=name,
        value=value,
        raw_hex=frame[offset : offset + size].hex(),
        byte_offset=offset,
        note=note,
    )


def parse_request(frame: bytes) -> ParseResult:
    """解析 FINS/TCP 请求帧 (0101 读请求 / 握手帧)。畸形帧记 errors 不抛。"""
    errors: list[str] = []
    fields: list[FrameField] = []
    try:
        command, error, payload = parse_tcp_header(frame)
    except ValueError as e:
        return ParseResult(protocol="fins", direction="req", fields=fields, valid=False, errors=[str(e)])
    fields.append(_field(frame, "tcp_command", command, 8, 4, TCP_COMMAND_NAMES.get(command, "")))
    fields.append(_field(frame, "tcp_error", error, 12, 4))
    if error != 0:
        errors.append(f"tcp error field nonzero: {error:#010x}")

    if command not in FINS_EXCHANGE_COMMANDS:
        # 握手帧: payload 即节点号, 无 FINS 层
        if command in (TCP_CMD_CONNECT_REQ, TCP_CMD_CONNECT_CFM) and len(payload) >= 4:
            (node,) = struct.unpack_from(">I", payload, 0)
            fields.append(_field(frame, "node_number", node, TCP_HEADER_LEN, 4))
        return ParseResult(protocol="fins", direction="req", fields=fields, valid=not errors, errors=errors)

    if len(payload) < FINS_HEADER_LEN + 2:
        errors.append(f"fins payload too short: {len(payload)} < {FINS_HEADER_LEN + 2}")
        return ParseResult(protocol="fins", direction="req", fields=fields, valid=False, errors=errors)
    off = TCP_HEADER_LEN
    icf, rsv, gct = payload[0], payload[1], payload[2]
    fields.append(_field(frame, "icf", icf, off, 1, "bit6=响应标志(bit6=0为请求), bit7=网关禁止(通常置位)"))
    fields.append(_field(frame, "rsv", rsv, off + 1, 1))
    fields.append(_field(frame, "gct", gct, off + 2, 1, "网关允许次数, 通常 2"))
    for i, name in enumerate(("dna", "da1", "da2", "sna", "sa1", "sa2")):
        fields.append(_field(frame, name, payload[3 + i], off + 3 + i, 1))
    sid = payload[9]
    fields.append(_field(frame, "sid", sid, off + 9, 1, "service id, 请求-响应配对"))
    (cmd,) = struct.unpack_from(">H", payload, 10)
    fields.append(_field(frame, "command_code", cmd, off + 10, 2))
    if cmd not in (CMD_MEMORY_AREA_READ, CMD_MEMORY_AREA_WRITE):
        errors.append(f"unsupported fins command {cmd:#06x} (supported: 0101 read, 0102 write)")
        return ParseResult(protocol="fins", direction="req", fields=fields, valid=False, errors=errors)
    if len(payload) < FINS_HEADER_LEN + 2 + 6:
        errors.append("fins memory request truncated: need area(1)+address(3)+count(2)")
        return ParseResult(protocol="fins", direction="req", fields=fields, valid=False, errors=errors)
    area = payload[12]
    word_addr = int.from_bytes(payload[13:15], "big")
    bit_addr = payload[15]
    count = int.from_bytes(payload[16:18], "big")
    fields.append(_field(frame, "area_code", area, off + 12, 1, AREA_CODE_NAMES.get(area, "")))
    fields.append(_field(frame, "address", word_addr, off + 13, 3, "字地址(2B 大端)+位地址(1B)"))
    fields.append(_field(frame, "bit_address", bit_addr, off + 15, 1))
    fields.append(_field(frame, "count", count, off + 16, 2))
    if bit_addr != 0:
        errors.append(f"bit address {bit_addr} != 0 (word read expected)")
    if area not in AREA_CODE_NAMES:
        errors.append(f"unknown area code {area:#04x}")
    if not 1 <= count <= MAX_READ_WORDS:
        errors.append(f"count {count} out of range 1-{MAX_READ_WORDS}")
    if cmd == CMD_MEMORY_AREA_WRITE and len(payload) > FINS_HEADER_LEN + 2 + 6:
        wdata = payload[FINS_HEADER_LEN + 2 + 6:]
        wwords = [int.from_bytes(wdata[j : j + 2], "big") for j in range(0, len(wdata) - 1, 2)]
        fields.append(_field(frame, "write_data", wwords, off + FINS_HEADER_LEN + 2 + 6, len(wdata), "write 16-bit BE words"))

    return ParseResult(protocol="fins", direction="req", fields=fields, valid=not errors, errors=errors)


def parse_response(frame: bytes, request: bytes | None = None) -> ParseResult:
    """解析 FINS/TCP 响应帧 (0101 读响应 / 握手确认)。

    request 提供时交叉校验: TCP 命令一致、SID 回显、数据字节数与请求
    count 匹配 (BUILD.md 注入清单: TC 帧长度不符、节点号重复在此暴露)。
    """
    errors: list[str] = []
    fields: list[FrameField] = []
    try:
        command, error, payload = parse_tcp_header(frame)
    except ValueError as e:
        return ParseResult(protocol="fins", direction="resp", fields=fields, valid=False, errors=[str(e)])
    fields.append(_field(frame, "tcp_command", command, 8, 4, TCP_COMMAND_NAMES.get(command, "")))
    fields.append(_field(frame, "tcp_error", error, 12, 4))
    if error != 0:
        errors.append(f"tcp error field nonzero: {error:#010x}")

    # IoTServer 等非标准实现对数据交换响应也回 cmd=0 而非 cmd=4。
    # 判别方式: 握手 payload = 8B (server+client node), 数据交换 payload >= 14B
    # (FINS header 10 + cmd 2 + end_code 2), 按 payload 长度分流。
    if command not in FINS_EXCHANGE_COMMANDS and len(payload) < FINS_HEADER_LEN + 4:
        # 握手确认走专门解析; 请求上下文校验命令配对
        if request is not None:
            try:
                req_cmd, _, _ = parse_tcp_header(request)
            except ValueError:
                req_cmd = None
            if req_cmd is not None and req_cmd != command:
                errors.append(f"tcp command mismatch: request {req_cmd:#010x}, response {command:#010x}")
        if command == TCP_CMD_CONNECT_CFM and len(payload) >= 8:
            server_node, client_node = struct.unpack_from(">II", payload, 0)
            fields.append(_field(frame, "server_node", server_node, TCP_HEADER_LEN, 4))
            fields.append(_field(frame, "client_node", client_node, TCP_HEADER_LEN + 4, 4))
        return ParseResult(protocol="fins", direction="resp", fields=fields, valid=not errors, errors=errors)

    if len(payload) < FINS_HEADER_LEN + 4:
        errors.append(f"fins payload too short: {len(payload)} < {FINS_HEADER_LEN + 4}")
        return ParseResult(protocol="fins", direction="resp", fields=fields, valid=False, errors=errors)
    off = TCP_HEADER_LEN
    icf = payload[0]
    fields.append(_field(frame, "icf", icf, off, 1))
    for i, name in enumerate(("dna", "da1", "da2", "sna", "sa1", "sa2")):
        fields.append(_field(frame, name, payload[3 + i], off + 3 + i, 1))
    sid = payload[9]
    fields.append(_field(frame, "sid", sid, off + 9, 1))
    (cmd,) = struct.unpack_from(">H", payload, 10)
    fields.append(_field(frame, "command_code", cmd, off + 10, 2))

    # IoTServer 等非标准实现的响应: FINS header 全零, cmd=0x0000, end_code=0x0000,
    # 数据直接跟在后面。检测到这种模式时跳过交叉校验和 cmd 校验。
    is_nonstandard = (
        cmd != CMD_MEMORY_AREA_READ
        and payload[:FINS_HEADER_LEN] == b"\x00" * FINS_HEADER_LEN
    )

    if request is not None and not is_nonstandard:
        errors.extend(_cross_check(frame, request))

    # 提前提取 end_code, 确保始终可用 (非标准响应也有的)
    (end_code,) = struct.unpack_from(">H", payload, 12)
    fields.append(_field(frame, "end_code", end_code, off + 12, 2, end_code_name(end_code)))

    if cmd not in (CMD_MEMORY_AREA_READ, CMD_MEMORY_AREA_WRITE) and not is_nonstandard:
        errors.append(f"unsupported fins command {cmd:#06x} in response")
        return ParseResult(protocol="fins", direction="resp", fields=fields, valid=False, errors=errors)
    data = payload[14:]
    if cmd == CMD_MEMORY_AREA_WRITE and not is_nonstandard:
        # 0102 写响应: end_code 之后不应再有任何数据
        if end_code != 0x0000 and data:
            errors.append(f"nonzero end code but {len(data)} trailing data bytes present")
        elif end_code == 0x0000 and data:
            errors.append(f"write response carries {len(data)} unexpected trailing data bytes")
        return ParseResult(protocol="fins", direction="resp", fields=fields, valid=not errors, errors=errors)
    if end_code != 0x0000:
        if data:
            errors.append(f"nonzero end code but {len(data)} trailing data bytes present")
        return ParseResult(protocol="fins", direction="resp", fields=fields, valid=not errors, errors=errors)
    if len(data) % 2 != 0:
        errors.append(f"odd data length {len(data)} for 16-bit word read")
    values = [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data) - 1, 2)]
    fields.append(
        _field(frame, "word_values", values, off + 14, len(data), "16-bit 大端字值")
    )
    return ParseResult(protocol="fins", direction="resp", fields=fields, valid=not errors, errors=errors)


def _cross_check(frame: bytes, request: bytes) -> list[str]:
    problems: list[str] = []
    try:
        req_cmd, _, req_payload = parse_tcp_header(request)
        _cmd, _err, payload = parse_tcp_header(frame)
    except ValueError:
        return problems
    if len(req_payload) >= 10 and len(payload) >= 10:
        req_sid = req_payload[9]
        sid = payload[9]
        if sid != req_sid:
            problems.append(f"sid mismatch: request {req_sid}, response {sid}")
        # 响应的 sa1 (源节点) 应等于请求的 da1 (目标节点)
        req_da1 = req_payload[4]
        resp_sa1 = payload[7]
        if resp_sa1 != req_da1:
            problems.append(
                f"node mismatch: request targeted node {req_da1}, response came from node {resp_sa1}"
            )
    return problems


# ---------------------------------------------------------------- validate


def validate_frame(frame: bytes, direction: Literal["req", "resp"] = "resp") -> list[CheckResult]:
    """FINS/TCP 校验清单: magic、TCP 长度一致性、命令合法、端结码、
    FINS 载荷完整性、目标节点字段。"""
    checks: list[CheckResult] = []
    checks.append(
        CheckResult(
            name="tcp_header_complete",
            passed=len(frame) >= TCP_HEADER_LEN,
            detail=f"got {len(frame)} bytes, need >= {TCP_HEADER_LEN}",
        )
    )
    if len(frame) < TCP_HEADER_LEN:
        return checks
    checks.append(
        CheckResult(
            name="magic_fins",
            passed=frame[:4] == TCP_MAGIC,
            detail=f"magic={frame[:4]!r} (expected b'FINS')",
        )
    )
    (length,) = struct.unpack_from(">I", frame, 4)
    command, error = struct.unpack_from(">II", frame, 8)
    checks.append(
        CheckResult(
            name="tcp_length_consistent",
            passed=length == len(frame) - 8,
            detail=f"length={length}, actual bytes after length field={len(frame) - 8}",
        )
    )
    checks.append(
        CheckResult(
            name="tcp_command_known",
            passed=command in TCP_COMMAND_NAMES,
            detail=f"command={command:#010x} ({TCP_COMMAND_NAMES.get(command, 'UNKNOWN')})",
        )
    )
    checks.append(
        CheckResult(
            name="tcp_error_zero",
            passed=error == 0,
            detail=f"error={error:#010x}" + (" (TCP 层错误)" if error else ""),
        )
    )
    if direction == "resp" and command == TCP_CMD_EXCHANGE:
        if len(frame) >= TCP_HEADER_LEN + FINS_HEADER_LEN + 4:
            (end_code,) = struct.unpack_from(">H", frame, TCP_HEADER_LEN + FINS_HEADER_LEN + 2)
            checks.append(
                CheckResult(
                    name="end_code_known",
                    passed=end_code in END_CODES,
                    detail=f"end_code={end_code:#06x} ({end_code_name(end_code)})",
                )
            )
        else:
            checks.append(
                CheckResult(
                    name="end_code_known",
                    passed=False,
                    detail="fins response too short to contain end code",
                )
            )
    return checks





