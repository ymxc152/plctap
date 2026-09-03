"""三协议 TCP 流分帧纯函数 (M3: listener 与 parse_pcap 共用)。

TCP 是流式协议: 单次 read 可能只收到半帧, 也可能一包含多帧。本模块只做
"从字节缓冲里切出完整帧" 这一件事, 不碰 socket。帧长判定 (各协议头部的
长度字段语义不同, 是知识库字节序素材):

- modbus: 头部 6B (tid2+pid2+length2 BE), length 字段 = 其后所有字节
  (unit1+PDU) → 帧长 = 6 + length
- fins: 头部 16B (magic4+length4 BE+command4+error4), length = 8 + payload
  → 帧长 = 8 + length
- melsec: 头部 11B, data_length (LE, 偏移 9) = 数据字节数 → 帧长 = 11 + data_length
"""

from __future__ import annotations

import struct

# 各协议定长头部字节数 (长度字段所在的头部)
FRAME_HEADER_LEN = {
    "modbus": 6,
    "fins": 16,
    "melsec": 11,
}

# 单帧最大长度护栏: 长度字段畸形 (损坏/错协议) 时防缓冲无限膨胀。
# modbus 按规范 PDU 上限 253 (帧长 = 6 + 1 + 253); fins/melsec 与各
# adapter 的收帧上限对齐 (fins 0x4000, melsec 0x2000)
MAX_FRAME_LEN = {
    "modbus": 260,
    "fins": 0x4000 + 16,
    "melsec": 0x2000 + 11,
}


def try_frame_len(protocol: str, buf: bytes) -> int | None:
    """buf 头部若已构成一帧返回帧长; 字节不够返回 None (还要更多数据);
    长度字段畸形 (超出护栏) 返回 0, 表示无法按该协议继续分帧。
    """
    hdr = FRAME_HEADER_LEN[protocol]
    if len(buf) < hdr:
        return None
    if protocol == "modbus":
        (length,) = struct.unpack_from(">H", buf, 4)
        total = 6 + length
    elif protocol == "fins":
        (length,) = struct.unpack_from(">I", buf, 4)
        total = 8 + length
    else:  # melsec
        (data_len,) = struct.unpack_from("<H", buf, 9)
        total = 11 + data_len
    if total > MAX_FRAME_LEN[protocol] or total < hdr:
        return 0
    if len(buf) < total:
        return None
    return total


def split_frames(protocol: str, data: bytes) -> tuple[list[bytes], bytes]:
    """把一段已聚合的流数据切成完整帧, 返回 (完整帧列表, 尾部半帧)。

    尾部半帧常见于抓包截断, 单独留出供 parse_pcap 报告 (截断本身是诊断
    信息, 不静默丢弃)。长度字段畸形时剩余部分整体作半帧返回。
    """
    frames: list[bytes] = []
    buf = bytearray(data)
    while True:
        n = try_frame_len(protocol, buf)
        if n is None:
            break
        if n == 0:
            return frames, bytes(buf)
        frames.append(bytes(buf[:n]))
        del buf[:n]
    return frames, bytes(buf)
