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
    raise ValueError(f"parse_frame not implemented for {protocol!r} yet")


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
    """auto 规则: TCP 命令 0x00 (connect-req) 只出现在请求方向; 0x01/0x02
    只出现在响应方向; 0x04 (FINS 交换) 请求/响应同命令, 用 FINS 层 ICF
    bit6 判别 —— 规范规定响应帧 ICF 恒置 bit6 (通常 0xC0), 请求 0x80。
    """
    from plctap.protocols.fins import codec

    try:
        command, _error, payload = codec.parse_tcp_header(frame)
    except ValueError:
        # 头都不完整: 交给 parse_request 产出结构化错误证据
        return codec.parse_request(frame)
    if command == codec.TCP_CMD_CONNECT_REQ:
        return codec.parse_request(frame)
    if command in (codec.TCP_CMD_CONNECT_CFM, codec.TCP_CMD_CONNECT_REFUSED):
        return codec.parse_response(frame)
    if command == codec.TCP_CMD_EXCHANGE:
        if len(payload) >= codec.FINS_HEADER_LEN + 4 and payload[0] & 0x40:
            return codec.parse_response(frame)
        return codec.parse_request(frame)
    # 未知命令: 按响应尝试 (诊断场景抓到的多为设备回包)
    return codec.parse_response(frame)


def _parse_melsec(frame: bytes) -> ParseResult:
    """auto 规则: 请求与响应同副头部, 区分靠数据区首字 —— 请求首字是命令
    (M2 仅 0x0401), 响应首字是结束代码 (0x0000 或错误码, 错误码不与
    已知命令重叠)。头不完整时交给 parse_request 产出错误证据。
    """
    from plctap.protocols.melsec import codec

    if len(frame) >= codec.FRAME_HEADER_LEN + 2:
        (first_word,) = struct.unpack_from("<H", frame, codec.FRAME_HEADER_LEN)
        if first_word == codec.CMD_BATCH_READ_WORD:
            return codec.parse_request(frame)
        return codec.parse_response(frame)
    return codec.parse_request(frame)
