# -*- coding: utf-8 -*-
"""测试夹具: MELSEC MC 3E/4E x binary/ASCII 从站 (仅用于验证, 非通用模拟器).
用法: python mc_test_fixture.py [port] [--ascii-only]
D100..D109 = [11,22,33,44,55,66,77,88,0x4049,0x0FDB] (后两字 = float32 3.1415927)
支持 0401 读 / 1401 写 (D 区), 响应布局按 pymcprotocol 0.3.0 权威索引:
3E status@9/data@11, 4E status@13/data@15, 3E-ASCII status@18/data@22,
4E-ASCII status@26/data@30.
"""
import socket
import struct
import threading
import sys

D = [11, 22, 33, 44, 55, 66, 77, 88, 0x4049, 0x0FDB] + [0] * 22  # D100..D131
M_BITS = [0] * 64
D_BASE = 100

DEV_CODE_BIN = {"D": 0xA8, "M": 0x90, "W": 0xB4, "R": 0xAF, "X": 0x9C, "Y": 0x9D, "B": 0xA0}
BIN_CODE_DEV = {v: k for k, v in DEV_CODE_BIN.items()}
ASCII_BASE = {"X": 16, "Y": 16, "B": 16, "W": 16, "M": 10, "D": 10, "R": 10}

SUB_RESP_3E_BIN = bytes([0xD0, 0x00])
SUB_RESP_4E_BIN = bytes([0xD4, 0x00])


def read_words(dev: str, head: int, count: int) -> list:
    if dev == "D":
        base = head - D_BASE
        if base < 0 or base + count > len(D):
            return [0] * count
        return D[base:base + count]
    if dev in ("W", "R"):
        return [0x1111 + i for i in range(count)]
    if dev in ("X", "Y", "M", "B"):
        base = M_BITS if dev == "M" else [0] * 64
        words = []
        for w in range((count + 15) // 16):
            v = 0
            for b in range(16):
                idx = head + w * 16 + b
                if 0 <= idx < len(base) and base[idx]:
                    v |= 1 << b
            words.append(v)
        return words
    raise ValueError(dev)


def read_count_for(dev: str, count: int) -> int:
    return (count + 15) // 16 if dev in ("X", "Y", "M", "B") else count


def try_extract(buf: bytes):
    if len(buf) >= 2 and buf[0] in (0x50, 0x54) and buf[1] == 0:  # binary
        is4e = buf[0] == 0x54
        dlen_off = 11 if is4e else 7  # 数据长字段位置 (定时器之前)
        if len(buf) < dlen_off + 2:
            return None, buf
        (dlen,) = struct.unpack_from("<H", buf, dlen_off)
        total = dlen_off + 2 + dlen
        if len(buf) < total:
            return None, buf
        return buf[:total], buf[total:]
    if len(buf) >= 4 and buf[:1] in (b"5", b"D"):  # ascii
        dlen_off = 22 if buf[:4] == b"5400" else 14
        if len(buf) < dlen_off + 4:
            return None, buf
        try:
            dlen = int(buf[dlen_off:dlen_off + 4], 16)
        except ValueError:
            return None, buf
        total = dlen_off + 4 + dlen
        if len(buf) < total:
            return None, buf
        return buf[:total], buf[total:]
    return None, buf


def process(f: bytes):
    if f[1] == 0x00 and f[0] in (0x50, 0x54):  # binary
        is4e = f[0] == 0x54
        body = f[15:] if is4e else f[11:]
        cmd, subcmd = struct.unpack_from("<HH", body, 0)
        if cmd == 0x1401:  # 批量写字 -> 存入 D 区
            dev_num = int.from_bytes(body[4:7], "little")
            (count,) = struct.unpack_from("<H", body, 8)
            vals = struct.unpack_from("<%dH" % count, body, 10)
            for i, v in enumerate(vals):
                idx = dev_num - D_BASE + i
                if 0 <= idx < len(D):
                    D[idx] = v
            data = struct.pack("<H", 0)
            echo = f[2:11] if is4e else f[2:7]
            sub = SUB_RESP_4E_BIN if is4e else SUB_RESP_3E_BIN
            return sub + echo + struct.pack("<H", len(data)) + data
        if cmd != 0x0401:
            return None
        dev_num = int.from_bytes(body[4:7], "little")
        dev = BIN_CODE_DEV.get(body[7])
        if dev is None:
            return None
        (count,) = struct.unpack_from("<H", body, 8)
        words = read_words(dev, dev_num, read_count_for(dev, count))
        data = struct.pack("<H", 0) + b"".join(struct.pack("<H", w) for w in words)
        echo = f[2:11] if is4e else f[2:7]
        sub = SUB_RESP_4E_BIN if is4e else SUB_RESP_3E_BIN
        return sub + echo + struct.pack("<H", len(data)) + data
    # ascii
    is4e = f[:4] == b"5400"
    body = f[30:] if is4e else f[22:]  # 定时器之后
    cmd = int(body[0:4], 16)
    if cmd == 0x1401:
        devtxt = body[8:].decode()
        dev = devtxt[0]
        dev_num = int(devtxt[2:8], ASCII_BASE.get(dev, 10))
        count = int(devtxt[8:12], 16)
        for i in range(count):
            v = int(body[20 + i * 4:24 + i * 4], 16)  # cmd4+subcmd4+dev2+num6+count4=20
            idx = dev_num - D_BASE + i
            if dev == "D" and 0 <= idx < len(D):
                D[idx] = v
        data = b"0000"
        echo = f[4:22] if is4e else f[4:14]
        return (b"D400" if is4e else b"D000") + echo + ("%04X" % len(data)).encode() + data
    if cmd != 0x0401:
        return None
    devtxt = body[8:].decode()
    dev = devtxt[0]
    dev_num = int(devtxt[2:8], ASCII_BASE.get(dev, 10))
    count = int(devtxt[8:12], 16)
    words = read_words(dev, dev_num, read_count_for(dev, count))
    data = b"0000" + b"".join(("%04X" % (w & 0xFFFF)).encode() for w in words)
    echo = f[4:22] if is4e else f[4:14]
    return (b"D400" if is4e else b"D000") + echo + ("%04X" % len(data)).encode() + data


def handle(conn):
    buf = b""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            buf += data
            while True:
                frame, buf = try_extract(buf)
                if frame is None:
                    break
                resp = process_wrapped(frame)
                if resp:
                    conn.sendall(resp)
    except OSError:
        pass
    finally:
        conn.close()


ASCII_ONLY = "--ascii-only" in sys.argv


def process_wrapped(f: bytes):
    """--ascii-only: 收到 binary 请求回 ASCII 数据代码错误 (C059), 模拟 ASCII 配置设备。"""
    if ASCII_ONLY and len(f) >= 2 and f[1] == 0 and f[0] in (0x50, 0x54):
        is4e = f[0] == 0x54
        if is4e:
            return b"D400" + f[4:22] + b"0004" + b"C059"
        return b"D000" + f[4:14] + b"0004" + b"C059"
    return process(f)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    print("MC fixture slave on 127.0.0.1:%d" % port, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
