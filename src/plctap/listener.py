"""钓鱼模式监听 (M3 基础两档, PLAN.md 能力地图 + HANDOFF 决策 7)。

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
from plctap.protocols.melsec import codec as mc_codec

_LISTENER_FRAME_LIMIT = 1000  # 环形上限, 防长跑抓包内存膨胀

MODES = ("record_only", "respond_normal")
VALID_PROTOCOLS = tuple(streams.FRAME_HEADER_LEN)  # modbus / fins / melsec


@dataclass
class _Listener:
    protocol: str
    host: str
    requested_port: int
    port: int  # 实际绑定端口 (requested_port=0 时由系统分配)
    mode: str
    server: asyncio.AbstractServer
    frames: list[dict] = field(default_factory=list)
    sent: int = 0
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
        )
        self._listeners[actual_port] = lst
        return {
            "status": "listening",
            "protocol": protocol,
            "host": host,
            "port": actual_port,
            "mode": mode,
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
                if lst.mode != "respond_normal":
                    continue
                resp = build_normal_response(lst.protocol, frame, fins_node)
                if resp is None:
                    continue  # 未覆盖的请求: 记帧不回复
                if lst.protocol == "fins" and _fins_tcp_command(frame) == fins_codec.TCP_CMD_CONNECT_REQ:
                    fins_node = struct.unpack_from(">I", resp, fins_codec.TCP_HEADER_LEN)[0] & 0xFF
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
    return _melsec_response(frame)  # melsec


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
    if command != fins_codec.TCP_CMD_EXCHANGE or len(payload) < 18:
        return None
    if struct.unpack_from(">H", payload, 10)[0] != fins_codec.CMD_MEMORY_AREA_READ:
        return None  # 只回 0101 读 (写命令留 v1.1)
    # FINS 层: [ICF,RSV,GCT][DNA,DA1,DA2][SNA,SA1,SA2][SID][cmd 2B][area 1B][addr 2B][bit 1B][count 2B]
    (count,) = struct.unpack_from(">H", payload, 16)
    sid = payload[9]
    dna, da1, da2 = payload[3], payload[4], payload[5]
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
    return fins_codec.build_tcp_frame(fins_codec.TCP_CMD_EXCHANGE, fins)


def _melsec_response(frame: bytes) -> bytes | None:
    if len(frame) < mc_codec.FRAME_HEADER_LEN:
        return None
    data = frame[mc_codec.FRAME_HEADER_LEN:]
    if len(data) < 10:
        return None
    cmd, subcmd = struct.unpack_from("<HH", data, 0)
    if cmd != mc_codec.CMD_BATCH_READ_WORD:
        return None  # 只回 0401 批量读
    code = data[4]
    (count,) = struct.unpack_from("<H", data, 8)
    dev_name = mc_codec.DEVICE_CODE_NAMES.get(code)
    words = (count + 15) // 16 if dev_name in mc_codec.BIT_DEVICES else count
    resp_data = struct.pack("<H", 0x0000) + b"\x00" * (words * 2)  # 端结码 0 + 小端字值 0
    # 回显请求头部 (网络/PC/IO/站号/定时器), 重算 data_length
    return frame[:9] + struct.pack("<H", len(resp_data)) + resp_data


def _fins_tcp_command(frame: bytes) -> int | None:
    if len(frame) < fins_codec.TCP_HEADER_LEN:
        return None
    return struct.unpack_from(">I", frame, 8)[0]
