# -*- coding: utf-8 -*-
"""方向自动判别 (auto direction): 按帧结构推断请求/响应。

server.parse_frame 与 diag 引擎共用, 避免两处各养一套判别规则。
每个协议的判别依据写在对应函数 docstring —— "解析失败的方式"也是
诊断证据, 所以畸形帧交给 parse_request 产出结构化错误而不是抛异常。
"""

from __future__ import annotations

import struct

from plctap.models import ParseResult


def parse_auto(protocol: str, frame: bytes) -> ParseResult:
    if protocol == "modbus":
        return _parse_modbus(frame)
    if protocol == "fins":
        return _parse_fins(frame)
    if protocol == "melsec":
        return _parse_melsec(frame)
    if protocol == "iec104":
        return _parse_iec104(frame)
    if protocol == "enip":
        return _parse_enip(frame)
    raise ValueError(f"parse_frame not implemented for {protocol!r} yet")


def _parse_enip(frame: bytes) -> ParseResult:
    """auto 规则: ENIP 命令码客观判帧; 方向按命令语义。

    RegisterSession/ListIdentity 无会话时多为请求 (客户端发起),
    SendRRData 按请求侧解析 (嵌入 0x4C/0x4D 服务); 应答侧诊断走
    parse_response 显式指定。
    """
    from plctap.protocols.enip import codec

    try:
        command, _length, _session, _status, _off = codec.parse_enip_header(frame)
    except ValueError:
        return codec.parse_request(frame)
    if command in (codec.CMD_REGISTER_SESSION, codec.CMD_LIST_IDENTITY,
                   codec.CMD_UNREGISTER_SESSION):
        return codec.parse_request(frame)
    # SendRRData: 诊断场景多为设备应答 (含 CIP 状态/tag 数据), 走应答侧;
    # 请求侧 (嵌入 0x4C/0x4D) 解析失败时回退
    try:
        return codec.parse_response(frame)
    except ValueError:
        return codec.parse_request(frame)


def _parse_iec104(frame: bytes) -> ParseResult:
    """auto 规则: 帧型由控制域客观判定 (I/S/U), 方向仅在 I 格式内细分。

    I 格式: 控制方向类型 (命令 45-48/系统 100-107) -> req; 监视方向
    类型 (遥信遥测) -> resp。U/S 格式: 主站主动发起的 ACT/确认 -> req,
    设备回的 CON -> resp (按 U 功能码判断: _CON 结尾视为 resp)。
    """
    from plctap.protocols.iec104 import codec

    parsed = codec.parse_frame(frame)
    if parsed.direction != "auto" or len(frame) < 6:
        return parsed
    fmt = codec.apci_format(frame[2:6])
    if fmt == "U":
        parsed.direction = "resp" if frame[2] in (codec.U_STARTDT_CON, codec.U_STOPDT_CON,
                                                  codec.U_TESTFR_CON) else "req"
    elif fmt == "S":
        parsed.direction = "req"
    else:
        # I 格式: parse_frame 已按 type_id 判过; 控制方向类型再兜底
        return parsed
    return parsed


def _parse_modbus(frame: bytes) -> ParseResult:
    """auto 规则: ① 功能码 |0x80 只在响应方向出现 -> resp;
    ② fc01-06 请求帧恒为 12 字节 -> req (fc05/06 响应是请求的逐字节回显,
    两种解释字段一致, 优先 req 无信息损失);
    ③ 其余按响应解析 (诊断场景抓到的多为设备响应)。
    """
    from plctap.protocols.modbus import codec

    if len(frame) >= 8 and frame[7] & codec.EXCEPTION_FLAG:
        return codec.parse_response(frame)
    if len(frame) == 12 and len(frame) >= 8 and frame[7] in codec.KNOWN_FCS:
        return codec.parse_request(frame)
    return codec.parse_response(frame)


def _parse_fins(frame: bytes) -> ParseResult:
    """auto 规则 (FINS/TCP 方向判别)。

    判别维度有二: TCP 命令码 + FINS 载荷长度 + ICF bit6。

    TCP 命令码:
    - 0x00: 标准握手请求 (payload=4B 节点号)。但部分非标实现 (IoTServer/
      网关/第三方设备) 也用 0x00 回 FINS 数据交换响应 (payload>=14B)。
      按 payload 长度分流: 短 payload=握手 -> req, 长 payload=FINS 数据 -> resp。
    - 0x01: 握手确认 -> resp。
    - 0x02: Omron W463 规范定义为 "连接拒绝"; 但部分实现也用它做 FINS
      数据交换 (与 0x04 等价)。按 payload 长度+ICF bit6 分流。
    - 0x04: FINS 帧交换 (W463 规范/pyomron)。请求/响应同命令, 用 ICF
      bit6 判别: 响应帧 ICF 恒置 bit6 (0xC0), 请求 0x80。
    - 其他: 按响应尝试 (诊断场景抓到的多为设备回包)。

    FINS 载荷长度阈值: 握手帧 payload ≤ 8B (请求=节点号4B, 确认=双节点号8B);
    FINS 数据帧 payload ≥ 14B (FINS 头 10B + 命令码 2B + 端结码 2B)。
    """
    from plctap.protocols.fins import codec

    try:
        command, _error, payload = codec.parse_tcp_header(frame)
    except ValueError:
        # 头都不完整: 交给 parse_request 产出结构化错误证据
        return codec.parse_request(frame)

    # 握手帧 payload ≤ 8B; FINS 数据帧 payload ≥ FINS_HEADER_LEN(10)+4 = 14B
    is_fins_data = len(payload) >= codec.FINS_HEADER_LEN + 4

    if command == codec.TCP_CMD_CONNECT_REQ:  # 0x00
        if is_fins_data:
            # 非标设备 (IoTServer/网关) 用 cmd=0 回 FINS 数据交换响应
            return codec.parse_response(frame)
        return codec.parse_request(frame)

    if command == codec.TCP_CMD_CONNECT_CFM:  # 0x01
        return codec.parse_response(frame)

    if command == codec.TCP_CMD_CONNECT_REFUSED:  # 0x02
        if is_fins_data:
            # 部分实现用 0x02 做 FINS 数据交换 (等价 0x04)
            if payload[0] & 0x40:
                return codec.parse_response(frame)
            return codec.parse_request(frame)
        return codec.parse_response(frame)  # short payload = connection refused

    if command == codec.TCP_CMD_EXCHANGE:  # 0x04
        if is_fins_data and payload[0] & 0x40:
            return codec.parse_response(frame)
        return codec.parse_request(frame)

    # 未知命令: 按响应尝试 (诊断场景抓到的多为设备回包)
    return codec.parse_response(frame)


def _parse_melsec(frame: bytes) -> ParseResult:
    """auto 规则 (标准): 用副头部判别方向与帧格式。

    请求: 50 00 (3E) / 54 00 (4E); 响应: D0 00 (3E) / D4 00 (4E)。
    ASCII 帧: "5000"/"5400" 请求, "D000"/"D400" 响应。
    """
    from plctap.protocols.melsec import codec

    if len(frame) < 4:
        return codec.parse_request_fmt(frame, codec.FRAME_3E_BINARY)
    head4 = frame[0:4].decode("ascii", errors="ignore").upper()
    if head4 in ("5000", "5400"):
        fmt = codec.FRAME_4E_ASCII if head4 == "5400" else codec.FRAME_3E_ASCII
        return codec.parse_request_fmt(frame, fmt)
    if head4 in ("D000", "D400"):
        fmt = codec.FRAME_4E_ASCII if head4 == "D400" else codec.FRAME_3E_ASCII
        return codec.parse_response_fmt(frame, frame_format=fmt)
    (sub,) = struct.unpack_from(">H", frame, 0)
    if sub == 0x5000:
        return codec.parse_request_fmt(frame, codec.FRAME_3E_BINARY)
    if sub == 0xD000:
        return codec.parse_response_fmt(frame, frame_format=codec.FRAME_3E_BINARY)
    if sub == 0x5400:
        return codec.parse_request_fmt(frame, codec.FRAME_4E_BINARY)
    if sub == 0xD400:
        return codec.parse_response_fmt(frame, frame_format=codec.FRAME_4E_BINARY)
    # 未知副头部: 按响应尝试 (诊断场景抓到的多为设备回包)
    return codec.parse_response_fmt(frame, frame_format=codec.FRAME_3E_BINARY)
