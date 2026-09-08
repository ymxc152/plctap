"""钓鱼模式监听 (record_only / respond_normal 起步, v0.4 增 inject_errors)。

场景: 待测设备只能当 client 时, 起一个假 server 让设备来连, 钓出它的帧
行为, 再用 get_listener_frames + parse_frame/diagnose 逐帧分析。

- record_only: 收帧不回复 (纯被动)
- respond_normal: 对读类请求回最小"正常响应" (数据恒 0) —— 注意这是诊断
  设施不是通用模拟器 (HANDOFF 红线 4: ProtoForge 才是依赖); 只回读类请求,
  未覆盖/畸形请求记帧但不回复, 与 record_only 同效

实现要点:
- asyncio.start_server 每 listener 一个; 分帧用 streams.py (流式 TCP)
- 每个连接独立 handler; EOF / IncompleteReadError / 空闲超时一律 return ——
  continue 会形成无挂起自旋饿死事件循环 (M2 已踩过的坑)
- 帧存进程内存环形缓冲 (上限 _LISTENER_FRAME_LIMIT), get_listener_frames 读取
- respond_normal 的回包字节序必须与协议一致: modbus/fins 大端, melsec 小端
"""

from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass, field

from plctap import streams
from plctap.protocols.fins import codec as fins_codec
from plctap.protocols.enip import codec as enip_codec
from plctap.protocols.iec104 import codec as i104
from plctap.protocols.melsec import codec as mc_codec

_LISTENER_FRAME_LIMIT = 1000  # 环形上限, 防长跑抓包内存膨胀

MODES = ("record_only", "respond_normal", "inject_errors")
VALID_PROTOCOLS = tuple(streams.FRAME_HEADER_LEN)  # modbus / fins / melsec

# inject_errors 故障目录 (v0.4): 按 start 时给的 faults 列表轮转注入,
# 确定性可复现 —— 评测语料生产与诊断引擎回归的活水源头。
# 全协议通用: garbage = 回 8 字节全零 (对任何协议都不是合法帧)
FAULT_CATALOG: dict[str, frozenset[str]] = {
    "modbus": frozenset({"exception", "bad_length", "truncate", "garbage"}),
    "fins": frozenset({"end_code", "bad_length", "garbage"}),
    "melsec": frozenset({"end_code", "bad_length", "garbage"}),
}


def _apply_fault(protocol: str, request: bytes, resp: bytes, fault: str) -> bytes:
    """对已构造的正常响应做一次确定性故障注入 (纯函数)。

    request 提供请求上下文 (modbus exception 需要原 fc/unit 回显)。
    """
    if fault == "garbage":
        return b"\x00" * 8
    if protocol == "modbus":
        if fault == "exception" and len(request) >= 8:
            return (
                request[0:2]  # tid 回显
                + b"\x00\x00"
                + struct.pack(">H", 3)
                + request[6:7]
                + bytes([request[7] | 0x80, 0x02])  # ILLEGAL DATA ADDRESS
            )
        if fault == "bad_length" and len(resp) >= 6:
            return resp[:4] + struct.pack(">H", struct.unpack_from(">H", resp, 4)[0] + 1) + resp[6:]
        if fault == "truncate" and len(resp) > 8:
            return resp[:-2]
    if protocol == "fins":
        if fault == "end_code" and len(resp) >= 30:
            # FINS 层端结码 @ TCP头16 + FINS头10 + cmd 2, 2B BE
            return resp[:28] + struct.pack(">H", 0x1101) + resp[30:]
        if fault == "bad_length" and len(resp) >= 8:
            return resp[:4] + struct.pack(">I", struct.unpack_from(">I", resp, 4)[0] + 2) + resp[8:]
    if protocol == "melsec":
        # 端结码/数据长字段偏移随帧格式不同, 按响应副头部嗅探
        head2 = resp[:2]
        if head2 == b"\xd0\x00":
            end_off, dlen_off = 9, 7
        elif head2 == b"\xd4\x00":
            end_off, dlen_off = 13, 11
        elif resp[:4] == b"D000":
            end_off, dlen_off = 18, 14
        elif resp[:4] == b"D400":
            end_off, dlen_off = 26, 22
        else:
            end_off, dlen_off = None, None
        if fault == "end_code" and end_off is not None and len(resp) >= end_off + 2:
            return resp[:end_off] + struct.pack("<H", 0xC04F) + resp[end_off + 2 :]
        if fault == "bad_length" and dlen_off is not None and len(resp) >= dlen_off + 2:
            return resp[:dlen_off] + struct.pack("<H", struct.unpack_from("<H", resp, dlen_off)[0] + 2) + resp[dlen_off + 2 :]
    return resp  # 未知故障名/帧过短: 原样返回 (调用方已做目录校验, 这里兜底)


@dataclass
class _Listener:
    protocol: str
    host: str
    requested_port: int
    port: int  # 实际绑定端口 (requested_port=0 时由系统分配)
    mode: str
    server: asyncio.AbstractServer
    faults: list[str] = field(default_factory=list)  # inject_errors 的轮转注入序列
    frames: list[dict] = field(default_factory=list)
    sent: int = 0
    resp_count: int = 0  # 已注入响应数 (faults 轮转游标)
    started_at: float = field(default_factory=time.time)
    tasks: set[asyncio.Task] = field(default_factory=set)  # 活跃连接 handler


class ListenerRegistry:
    """port -> listener。所有状态活在进程内 (listener 本就是进程内服务)。"""

    def __init__(self) -> None:
        self._listeners: dict[int, _Listener] = {}

    async def start(
        self,
        protocol: str,
        host: str,
        port: int,
        mode: str,
        idle_timeout_sec: int = 120,
        faults: list[str] | None = None,
    ) -> dict:
        if protocol not in VALID_PROTOCOLS:
            raise ValueError(f"protocol must be one of {VALID_PROTOCOLS}, got {protocol!r}")
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        if not 0 <= port <= 65535:
            raise ValueError(f"port {port} out of range 0-65535")
        if not idle_timeout_sec > 0:
            raise ValueError(f"idle_timeout_sec must be > 0, got {idle_timeout_sec}")
        if port in self._listeners:
            raise ValueError(f"listener already running on port {port}")
        if mode == "inject_errors":
            if not faults:
                raise ValueError(
                    f"inject_errors requires faults; catalog: {sorted(FAULT_CATALOG[protocol])} + garbage"
                )
            unknown = [f for f in faults if f != "garbage" and f not in FAULT_CATALOG[protocol]]
            if unknown:
                raise ValueError(
                    f"unknown faults {unknown} for {protocol}; catalog: {sorted(FAULT_CATALOG[protocol])} + garbage"
                )
        elif faults:
            raise ValueError("faults is only valid with mode='inject_errors'")
        # 端口可能被抢占 (port=0 由系统分配): 先登记后校验, 冲突由系统抛错

        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await self._serve(lst, reader, writer, float(idle_timeout_sec))

        def _spawn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            t = asyncio.ensure_future(_handler(reader, writer))
            lst.tasks.add(t)
            t.add_done_callback(lst.tasks.discard)

        server = await asyncio.start_server(_spawn, host, port)
        actual_port = server.sockets[0].getsockname()[1]
        lst = _Listener(
            protocol=protocol,
            host=host,
            requested_port=port,
            port=actual_port,
            mode=mode,
            server=server,
            faults=list(faults) if faults else [],
        )
        self._listeners[actual_port] = lst
        return {
            "status": "listening",
            "protocol": protocol,
            "host": host,
            "port": actual_port,
            "mode": mode,
            "faults": lst.faults,
            "recorded": 0,
        }

    async def stop(self, port: int) -> dict:
        lst = self._listeners.pop(port, None)
        if lst is None:
            raise ValueError(f"no listener on port {port}")
        lst.server.close()
        for t in list(lst.tasks):
            t.cancel()
        await asyncio.gather(*lst.tasks, return_exceptions=True)
        lst.tasks.clear()
        await lst.server.wait_closed()
        return {
            "status": "stopped",
            "port": port,
            "mode": lst.mode,
            "recorded": len(lst.frames),
            "sent": lst.sent,
        }

    def frames(self, port: int, limit: int = 100) -> list[dict]:
        lst = self._listeners.get(port)
        if lst is None:
            raise ValueError(f"no listener on port {port}")
        return list(lst.frames[-limit:])

    def active_ports(self) -> list[int]:
        return sorted(self._listeners)

    # ------------------------------------------------------------ 连接处理

    async def _serve(
        self,
        lst: _Listener,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float,
    ) -> None:
        peer = str(writer.get_extra_info("peername"))
        fins_node: int | None = None  # FINS 握手分配的 server 节点 (按连接)
        try:
            while True:
                frame = await self._recv_frame(lst.protocol, reader, timeout)
                if frame is None:
                    return  # EOF/超时/畸形: 结束该连接 (continue 会自旋)
                self._record(lst, "recv", peer, frame)
                if lst.mode == "record_only":
                    continue
                resp = build_normal_response(lst.protocol, frame, fins_node)
                if resp is None:
                    continue  # 未覆盖的请求: 记帧不回复
                if lst.protocol == "fins" and _fins_tcp_command(frame) == fins_codec.TCP_CMD_CONNECT_REQ:
                    fins_node = struct.unpack_from(">I", resp, fins_codec.TCP_HEADER_LEN)[0] & 0xFF
                    writer.write(resp)
                    await asyncio.wait_for(writer.drain(), timeout)
                    self._record(lst, "send", peer, resp)
                    continue  # 握手确认不参与故障轮转 (设备需完成握手才继续吐帧)
                if lst.mode == "inject_errors" and lst.faults:
                    resp = _apply_fault(lst.protocol, frame, resp, lst.faults[lst.resp_count % len(lst.faults)])
                    lst.resp_count += 1
                writer.write(resp)
                await asyncio.wait_for(writer.drain(), timeout)
                self._record(lst, "send", peer, resp)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

    async def _recv_frame(
        self, protocol: str, reader: asyncio.StreamReader, timeout: float
    ) -> bytes | None:
        """按协议分帧收一帧。EOF / IncompleteReadError / 空闲超时 / 畸形长度
        字段都返回 None (断开连接) —— 与"没数据继续等"的 TimeoutError 不同,
        EOF 后 continue 会形成无挂起自旋饿死事件循环。
        """
        buf = bytearray()
        while True:
            n = streams.try_frame_len(protocol, buf)
            if n == 0:
                return None  # 长度字段畸形, 无法继续
            if n is not None:
                return bytes(buf[:n])
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout)
            except TimeoutError:
                return None  # 空闲超时 (设备不说话了)
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                return None  # EOF / 连接异常
            if not chunk:
                return None  # EOF
            buf.extend(chunk)

    def _record(self, lst: _Listener, direction: str, peer: str, frame: bytes) -> None:
        lst.frames.append(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "direction": direction,
                "peer": peer,
                "frame_hex": frame.hex(),
            }
        )
        if direction == "send":
            lst.sent += 1
        if len(lst.frames) > _LISTENER_FRAME_LIMIT:
            del lst.frames[: len(lst.frames) - _LISTENER_FRAME_LIMIT]


# ---------------------------------------------------------------- respond_normal


def build_normal_response(protocol: str, frame: bytes, fins_node: int | None = None) -> bytes | None:
    """给读类请求构造最小"正常响应"。返回 None 表示未覆盖 (只记帧不回复)。

    数据恒为 0: 目的只是让设备认为链路正常从而继续吐帧, 不是模拟业务数据。
    """
    if protocol == "modbus":
        return _modbus_response(frame)
    if protocol == "fins":
        return _fins_response(frame, fins_node)
    if protocol == "iec104":
        return _iec104_response(frame)
    if protocol == "enip":
        return _enip_response(frame)
    return _melsec_response(frame)  # melsec


def _iec104_response(frame: bytes) -> bytes | None:
    """104 钓鱼回帧: U 握手回 CON; 总召 ACT -> ACT_CON + 罐头监视帧 + ACT_TERM。

    I 帧序号: 我方发送序号取请求帧的 rx_seq (确认对方已收到的量),
    我方接收确认回显请求 tx_seq —— 无状态服务的最小合规实现。
    罐头监视数据恒定: 单点遥信 200..207 交替真假, 短浮点 300..303 = 0.25*i。
    """
    if len(frame) < 6 or frame[0] != i104.START_BYTE:
        return None
    fmt = i104.apci_format(frame[2:6])
    if fmt == "U":
        con = {i104.U_STARTDT_ACT: i104.U_STARTDT_CON,
               i104.U_TESTFR_ACT: i104.U_TESTFR_CON,
               i104.U_STOPDT_ACT: i104.U_STOPDT_CON}.get(frame[2])
        return i104.build_apci_u(con) if con else None
    if fmt != "I" or len(frame) <= 6:
        return None  # S 帧/空 I 帧: 无需回应
    req = i104.parse_asdu(frame, i104.APCI_LEN, len(frame) - 6)
    fields = {f.name: f.value for f in req.fields}
    if fields.get("type_id") != i104.C_IC_NA_1 or fields.get("cot") != 6:
        return None
    tx = _apci_seq(frame, 1)  # 对方接收序号 = 我方发送序号
    rx = _apci_seq(frame, 0)
    ca = fields.get("common_address", 1)
    frames = []
    # ACT_CON (回显请求 ASDU, COT 6 -> 7)
    act_con = bytearray(frame[6:])
    act_con[2] = 7 & 0xFF
    act_con[3] = 0
    frames.append(i104.build_apci_i(tx, rx, bytes(act_con)))
    # 罐头: 单点遥信 200..207 (SQ=0, COT 20 站总召)
    tx = (tx + 1) & 0x7FFF
    sp = [(200 + i, [0x01 if i % 2 == 0 else 0x00]) for i in range(8)]
    frames.append(i104.build_apci_objects(i104.M_SP_NA_1, sp, 20, ca, tx, rx))
    # 罐头: 短浮点 300..303
    tx = (tx + 1) & 0x7FFF
    import struct as _s
    nc = [(300 + i, list(_s.pack("<f", 0.25 * i)) + [0]) for i in range(4)]
    frames.append(i104.build_apci_objects(i104.M_ME_NC_1, nc, 20, ca, tx, rx))
    # ACT_TERM
    tx = (tx + 1) & 0x7FFF
    act_term = bytearray(frame[6:])
    act_term[2] = 10 & 0xFF
    act_term[3] = 0
    frames.append(i104.build_apci_i(tx, rx, bytes(act_term)))
    return b"".join(frames)


def _apci_seq(frame: bytes, idx: int) -> int:
    """I 帧控制域第 idx 个 16 位字 -> 15bit 序号 (idx 0=发送, 1=接收)。"""
    import struct as _s
    (w,) = _s.unpack_from("<H", frame, 2 + idx * 2)
    return w >> 1


def _enip_response(frame: bytes) -> bytes | None:
    """ENIP 钓鱼回帧: RegisterSession 授予句柄 1, ListIdentity 回罐头身份,
    SendRRData 的 0x4C 读回罐头 DINT/REAL, 0x4D 写回成功应答, 未知 tag 回
    CIP status 0x05 (PATH_DESTINATION_UNKNOWN)。"""
    try:
        (command, _length, _session, _status, off) = enip_codec.parse_enip_header(frame)
    except ValueError:
        return None
    if command == enip_codec.CMD_REGISTER_SESSION:
        return enip_codec.build_enip(enip_codec.CMD_REGISTER_SESSION,
                                     frame[off:], session=1)
    if command == enip_codec.CMD_LIST_IDENTITY:
        ident = (
            struct.pack("<H", 1) + b"\x00" * 16
            + struct.pack("<I", 1) + struct.pack("<H", 12) + struct.pack("<H", 66)
            + bytes([1, 5]) + struct.pack("<H", 0) + struct.pack("<I", 0xC0FFEE)
            + bytes([14]) + b"plctap-fixture"
        )
        payload = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(ident)) + ident
        return enip_codec.build_enip(enip_codec.CMD_LIST_IDENTITY, payload, session=1)
    if command != enip_codec.CMD_SEND_RR_DATA:
        return None
    # SendRRData: 解嵌入的 0x4C 读 / 0x4D 写
    try:
        (_iface, _timeout, nitems) = struct.unpack_from("<IHH", frame, off)
        if nitems != 2:
            return None
        o = off + 8
        addr_type, addr_len = struct.unpack_from("<HH", frame, o)
        o += 4 + addr_len
        data_type, data_len = struct.unpack_from("<HH", frame, o)
        o += 4
        cip = frame[o:o + data_len]
        session = struct.unpack_from("<I", frame, 4)[0]
    except struct.error:
        return None
    if not cip or cip[0] not in (0x4C, 0x4D):
        return None
    if cip[0] == 0x4D:
        reply = bytes([enip_codec.SVC_WRITE_TAG_REPLY, 0x00, 0x00, 0x00])
        cip_out = reply
    else:
        # 读: 解 tag 名 (0x91 符号段, 扫描式 —— 兼容带 MR 路径前缀的请求),
        # 罐头值: alpha*=DINT 42/43, beta*=REAL 0.25/0.5; 元素数 = 尾部 2 字节
        try:
            name, count = _enip_parse_symbol_and_count(cip)
        except (struct.error, IndexError, ValueError):
            return None
        if name.startswith("alpha"):
            cip_out = (bytes([0xCC, 0x00, 0x00, 0x00]) + struct.pack("<H", 0xC4)
                       + b"".join(struct.pack("<I", 42 + i) for i in range(count)))
        elif name.startswith("beta"):
            words = []
            for i in range(count):
                bits = struct.unpack("<I", struct.pack("<f", 0.25 * (i + 1)))[0]
                words.extend(struct.pack("<HH", bits & 0xFFFF, bits >> 16))
            cip_out = (bytes([0xCC, 0x00, 0x00, 0x00]) + struct.pack("<HH", 0xCA, count)
                       + b"".join(words))
        else:
            cip_out = bytes([0xCC, 0x00, 0x05, 0x00, 0x00])  # CIP status 0x05
    return enip_codec.build_send_rr_data(session, cip_out)


def _enip_parse_symbol_and_count(cip: bytes) -> tuple[str, int]:
    """从 Read Tag 请求 CIP 里解 (符号名, 元素数): 扫描 0x91 符号段。"""
    i = 0
    while i < len(cip) - 2:
        if cip[i] == 0x91:
            name_len = cip[i + 1]
            name = cip[i + 2:i + 2 + name_len].decode("ascii", errors="replace")
            (count,) = struct.unpack_from("<H", cip, len(cip) - 2)
            return name, count
        i += 1
    raise ValueError("no symbolic segment")


def _modbus_response(frame: bytes) -> bytes | None:
    if len(frame) < 8:
        return None
    tid, unit = frame[0:2], frame[6]
    fc = frame[7]
    if fc in (5, 6) and len(frame) >= 12:
        return frame  # 写单点响应 = 请求逐字节回显 (读回显/写确认同一形状)
    if fc in (1, 2, 3, 4) and len(frame) >= 12:
        (quantity,) = struct.unpack_from(">H", frame, 10)
        byte_count = (quantity + 7) // 8 if fc in (1, 2) else quantity * 2
        pdu = bytes([fc, byte_count]) + b"\x00" * byte_count
        return tid + b"\x00\x00" + struct.pack(">H", 1 + len(pdu)) + bytes([unit]) + pdu
    return None


def _fins_response(frame: bytes, server_node: int | None) -> bytes | None:
    if len(frame) < fins_codec.TCP_HEADER_LEN:
        return None
    (command,) = struct.unpack_from(">I", frame, 8)
    payload = frame[fins_codec.TCP_HEADER_LEN:]
    if command == fins_codec.TCP_CMD_CONNECT_REQ and len(payload) >= 4:
        # 节点连接请求: payload = client_node(4B BE) -> 确认 (server_node + client_node)
        client_node = struct.unpack_from(">I", payload, 0)[0] & 0xFF
        node = 2 if client_node != 2 else 3  # 不与客户端节点撞号
        return fins_codec.build_tcp_frame(
            fins_codec.TCP_CMD_CONNECT_CFM, struct.pack(">II", node, client_node)
        )
    if command not in fins_codec.FINS_EXCHANGE_COMMANDS or len(payload) < 18:
        return None  # 数据帧 TCP 命令 0x02 (主流) / 0x04 (变体) 皆接受
    if struct.unpack_from(">H", payload, 10)[0] != fins_codec.CMD_MEMORY_AREA_READ:
        return None  # 只回 0101 读 (写命令留 v1.1)
    # FINS 层: [ICF,RSV,GCT][DNA,DA1,DA2][SNA,SA1,SA2][SID][cmd 2B][area 1B][addr 2B][bit 1B][count 2B]
    (count,) = struct.unpack_from(">H", payload, 16)
    sid = payload[9]
    sna, sa1, sa2 = payload[6], payload[7], payload[8]
    # 响应路由 = 请求路由对调; 响应端节点 (SNA/SA1) 用握手分配的 server 节点
    fins = (
        bytes([0x40, 0x00, 0x02])  # ICF=响应(bit6 置位), RSV=0, GCT=2
        + bytes([sna, sa1, sa2])
        + bytes([0x00, server_node or 0, 0x00])
        + bytes([sid])
        + struct.pack(">H", fins_codec.CMD_MEMORY_AREA_READ)
        + struct.pack(">H", 0x0000)  # 端结码 正常
        + b"\x00" * (count * 2)  # 全大端字值 0
    )
    # 回显请求使用的 TCP 数据命令 (0x02/0x04), 与请求方实现保持一致
    return fins_codec.build_tcp_frame(command, fins)


def _melsec_response(frame: bytes) -> bytes | None:
    """MELSEC 0401 批量读的 respond_normal 回帧, 支持全部 4 种帧格式。

    按副头部判别请求格式 (50 00/54 00 二进制, "5000"/"5400" ASCII),
    路由回显 + 数据长 + 端结码 0 + 全零字数据 (小端/ASCII hex)。
    """
    # 格式判别 (与 adapter._RESP_SUBHEADER_TO_FORMAT 同规则)
    if len(frame) >= 2 and frame[1] == 0 and frame[0] in (0x50, 0x54):
        fmt = "4e_binary" if frame[0] == 0x54 else "3e_binary"
    elif len(frame) >= 4 and frame[:1] in (b"5", b"D"):
        fmt = "4e_ascii" if frame[:4] == b"5400" else "3e_ascii"
    else:
        return None
    is_ascii = fmt.endswith("ascii")
    is_4e = fmt.startswith("4e")
    hdr = 30 if (is_ascii and is_4e) else 22 if is_ascii else 15 if is_4e else 11
    if len(frame) < hdr:
        return None
    body = frame[hdr:]
    if len(body) < 10:
        return None
    cmd, _subcmd, code, _head, count = mc_codec._decode_pdu(fmt, body)
    if cmd != mc_codec.CMD_BATCH_READ_WORD:
        return None  # 只回 0401 批量读
    dev_name = mc_codec.DEVICE_CODE_NAMES.get(code)
    words = (count + 15) // 16 if dev_name in mc_codec.BIT_DEVICES else count
    if is_ascii:
        resp_data = f"{0:04X}".encode() + b"".join(f"{0:04X}".encode() for _ in range(words))
        echo = frame[4:22] if is_4e else frame[4:14]
        sub = b"D400" if is_4e else b"D000"
        return sub + echo + f"{len(resp_data):04X}".encode() + resp_data
    resp_data = struct.pack("<H", 0x0000) + b"\x00" * (words * 2)  # 端结码 0 + 小端字值 0
    echo = frame[2:11] if is_4e else frame[2:7]
    sub = b"\xd4\x00" if is_4e else b"\xd0\x00"
    return sub + echo + struct.pack("<H", len(resp_data)) + resp_data


def _fins_tcp_command(frame: bytes) -> int | None:
    if len(frame) < fins_codec.TCP_HEADER_LEN:
        return None
    return struct.unpack_from(">I", frame, 8)[0]
