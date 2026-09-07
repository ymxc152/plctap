"""三协议 TCP 流分帧纯函数 (M3: listener 与 parse_pcap 共用)。

TCP 是流式协议: 单次 read 可能只收到半帧, 也可能一包含多帧。本模块只做
"从字节缓冲里切出完整帧" 这一件事, 不碰 socket。帧长判定 (各协议头部的
长度字段语义不同, 是知识库字节序素材):

- modbus: 头部 6B (tid2+pid2+length2 BE), length 字段 = 其后所有字节
  (unit1+PDU) → 帧长 = 6 + length
- fins: 头部 16B (magic4+length4 BE+command4+error4), length = 8 + payload
  → 帧长 = 8 + length
- melsec: 按副头部判别 4 种帧格式 (50 00/54 00 二进制, "5000"/"5400" ASCII),
  数据长字段位置随格式不同:
  3E binary  数据长 2B LE @7  → 帧长 = 9  + data_length
  4E binary  数据长 2B LE @11 → 帧长 = 13 + data_length
  3E ASCII   数据长 4 字符 @14 → 帧长 = 18 + data_length (按字符计)
  4E ASCII   数据长 4 字符 @22 → 帧长 = 26 + data_length (按字符计)
- iec104: 头部 2B (启动 0x68 + APDU 长度, 长度 = 控制域 4B + 载荷)
  → 帧长 = 2 + APDU 长度
"""

from __future__ import annotations

import struct

# 各协议定长头部字节数 (长度字段所在的头部)
FRAME_HEADER_LEN = {
    "modbus": 6,
    "fins": 16,
    "melsec": 11,
    "iec104": 2,
    "enip": 24,
}

# 单帧最大长度护栏: 长度字段畸形 (损坏/错协议) 时防缓冲无限膨胀。
# modbus 按规范 PDU 上限 253 (帧长 = 6 + 1 + 253); fins 与 adapter 收帧
# 上限对齐 (0x4000); melsec 取二进制 (0x2000) 与 ASCII 按字符计 (约两倍)
# 两档的上界; iec104 按规范 APDU 上限 253 (帧长 = 2 + 253)
MAX_FRAME_LEN = {
    "modbus": 260,
    "fins": 0x4000 + 16,
    "melsec": 0x4000 + 32,
    "iec104": 255,
    "enip": 0xFFFF + 24,
}


def _melsec_frame_len(buf: bytes) -> int | None:
    """按副头部判别 MELSEC 帧格式并算帧长 (请求/响应两侧, 语义同 try_frame_len)。

    副头部: 请求 50 00 (3E) / 54 00 (4E), 响应 D0 00 (3E) / D4 00 (4E);
    ASCII 为文本 "5000"/"5400"/"D000"/"D400"。
    """
    if len(buf) < 2:
        return None
    if buf[1] == 0 and buf[0] in (0x50, 0xD0):
        dlen_off, sz = 7, 2  # 3E 二进制
    elif buf[1] == 0 and buf[0] in (0x54, 0xD4):
        dlen_off, sz = 11, 2  # 4E 二进制
    elif buf[:1] in (b"5", b"D"):
        if len(buf) < 4:
            return None
        dlen_off, sz = (22, 4) if buf[:4] in (b"5400", b"D400") else (14, 4)
    else:
        return 0  # 无法识别的帧头
    if len(buf) < dlen_off + sz:
        return None
    if sz == 4:  # ASCII 数据长按字符计
        try:
            dlen = int(buf[dlen_off:dlen_off + 4], 16)
        except ValueError:
            return 0
    else:
        (dlen,) = struct.unpack_from("<H", buf, dlen_off)
    return dlen_off + sz + dlen


def try_frame_len(protocol: str, buf: bytes) -> int | None:
    """buf 头部若已构成一帧返回帧长; 字节不够返回 None (还要更多数据);
    长度字段畸形 (超出护栏) 返回 0, 表示无法按该协议继续分帧。
    """
    hdr = FRAME_HEADER_LEN[protocol]
    if protocol == "melsec":
        n = _melsec_frame_len(bytes(buf))
        if n is None:
            return None
        if n > MAX_FRAME_LEN[protocol] or n <= 0:
            return 0
        if len(buf) < n:
            return None
        return n
    if len(buf) < hdr:
        return None
    if protocol == "modbus":
        (length,) = struct.unpack_from(">H", buf, 4)
        total = 6 + length
    elif protocol == "iec104":
        if buf[0] != 0x68 or not 4 <= buf[1] <= 253:
            return 0
        total = 2 + buf[1]
    elif protocol == "enip":
        (cmd, _len) = struct.unpack_from("<HH", buf, 0)
        if cmd not in (0x0063, 0x0065, 0x0066, 0x006F, 0x0070):
            return 0
        total = 24 + _len
    else:  # fins
        (length,) = struct.unpack_from(">I", buf, 4)
        total = 8 + length
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
