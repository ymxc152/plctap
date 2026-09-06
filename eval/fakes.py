"""进程内最小 fake server 工厂 (detect 档评测专用, eval/benchmark.py)。

与 tests/test_adapter_*.py 的会话替身同思路 (复制改造, CI 无外部依赖),
面向评测 runner 做了三件事:
- 统一 start() -> (host, port) / stop() 生命周期, port=0 系统分配;
- start_fake(spec) 按 corpus 条目 input.fakes 描述起 fake, 并做一次
  "归属探测" —— Windows 上已有通配 (0.0.0.0) 监听时, 具体地址 bind 仍会
  成功但连接去向不定 (实测本机 9600 被外部进程占用仍可 bind), 起一个
  探测连接确认请求真的进到本 fake, 否则视为端口不可用;
- 端口不可用时按 spec.required_port 决定: true 抛 PortUnavailable
  (先验端口语义, 由 runner 记 SKIP), false 回退系统分配端口。

四种 fake:
- modbus  fc03 回自洽响应, 寄存器值 (addr+i)*3+preset (preset 默认 7, 非零,
  deep 读可验证读到数);
- fins    节点握手回 cfm, 0101 读回端结码 0 + 数据 0x1000+i;
- melsec  3E binary 0401 读回端结码 0 + 数据 0x2000+i;
- echo    未知回显服务, 收到什么回什么 (detect 的 unknown_services 判定)。

纪律 (与 tests 同): EOF 一律 return —— readexactly 撞到对端关闭必须退出,
否则循环会同步自旋饿死事件循环; stop() 关全部残余连接保证 handler 退出。
"""

from __future__ import annotations

import asyncio
import struct

from plctap.protocols.fins import codec as fins_codec
from plctap.protocols.melsec import codec as mc_codec

__all__ = [
    "PortUnavailable",
    "FakeModbusServer",
    "FakeFinsServer",
    "FakeMelsecServer",
    "FakeEchoServer",
    "build_fake",
    "start_fake",
]


class PortUnavailable(RuntimeError):
    """首选端口无法布置 (被其他进程占用 / 连接不进本 fake)。"""


class _FakeServerBase:
    """公共生命周期: 监听 + 连接计数 (归属探测用) + 干净收尾。"""

    kind = "?"

    def __init__(self, port: int = 0) -> None:
        self.bind_port = int(port)
        self.addr: tuple[str, int] = ("127.0.0.1", 0)
        self.server: asyncio.Server | None = None
        self.conn_count = 0
        self._conn_evt = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> tuple[str, int]:
        self.server = await asyncio.start_server(
            self._handle, self.addr[0], self.bind_port
        )
        self.addr = ("127.0.0.1", self.server.sockets[0].getsockname()[1])
        return self.addr

    async def stop(self) -> None:
        """关全部残余连接 + 监听, 保证 handler 退出 (幂等)。"""
        for w in list(self._writers):
            w.close()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def wait_connection(self, timeout: float = 1.0) -> None:
        """归属探测: 起一条连接并确认它进到了本 fake 的 handler。

        连接没进来 (被同端口的外部监听截走) -> 超时, 调用方视为端口
        不可用。探测连接本身即样本, handler 收到后按各自协议正常容错。
        """
        self.conn_count = 0
        self._conn_evt = asyncio.Event()
        reader, writer = await asyncio.open_connection(*self.addr)
        try:
            await asyncio.wait_for(self._conn_evt.wait(), timeout)
        finally:
            writer.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.conn_count += 1
        self._conn_evt.set()
        self._writers.add(writer)
        try:
            await self._serve(reader, writer)
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            TimeoutError,
            OSError,
            struct.error,
            IndexError,
            ValueError,
        ):
            pass  # 对端 EOF/异常帧/探测连接即断: 一律当作连接结束 (EOF=return)
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        raise NotImplementedError


class FakeModbusServer(_FakeServerBase):
    """最小 Modbus/TCP 从站: fc03 读回自洽响应, fc05/06/16 写请求回显。

    寄存器值 = (addr + i) * 3 + preset, preset 默认 7 (地址 0 读回 7,
    非零, 供 detect deep 读验证)。
    """

    kind = "modbus"

    def __init__(self, port: int = 0, preset: int = 7) -> None:
        super().__init__(port)
        self.preset = int(preset)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            head = await reader.readexactly(7)  # MBAP: tid/pid/len/uid
            length = struct.unpack_from(">H", head, 4)[0]
            if length < 1:
                return  # 垃圾流量容错: 长度字段不合法
            rest = await reader.readexactly(length - 1)
            fc = rest[0]
            if fc in (5, 6, 16):
                # 写请求: 响应为请求 PDU 逐字节回显 (规范 6.5/6.6 节)
                writer.write(head[:4] + struct.pack(">H", len(rest) + 1) + head[6:7] + rest)
                await writer.drain()
                continue
            _addr, qty = struct.unpack_from(">HH", rest, 1)
            data = b"".join(
                struct.pack(">H", (_addr + i) * 3 + self.preset) for i in range(qty)
            )
            pdu = struct.pack(">BB", fc, len(data)) + data
            writer.write(head[:4] + struct.pack(">H", len(pdu) + 1) + head[6:7] + pdu)
            await writer.drain()


class FakeFinsServer(_FakeServerBase):
    """最小 FINS/TCP 设备: 节点握手回 cfm, 0101 读回端结码 0 + 数据。"""

    kind = "fins"

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            head = await reader.readexactly(fins_codec.TCP_HEADER_LEN)
            (length,) = struct.unpack_from(">I", head, 4)
            if length < 8:
                return  # 垃圾流量容错: TCP 长度字段连命令+错误都装不下
            payload = await reader.readexactly(length - 8)
            (command,) = struct.unpack_from(">I", head, 8)
            if command == fins_codec.TCP_CMD_CONNECT_REQ:
                (client_node,) = struct.unpack_from(">I", payload, 0)
                resp = struct.pack(">II", 0x02, client_node)
                writer.write(fins_codec.build_tcp_frame(fins_codec.TCP_CMD_CONNECT_CFM, resp))
                await writer.drain()
            elif command in fins_codec.FINS_EXCHANGE_COMMANDS:
                sid = payload[9]
                da1 = payload[4]
                (fins_cmd,) = struct.unpack_from(">H", payload, 10)
                fins = (
                    bytes([0xC0, 0x00, 0x02])  # 响应 ICF/RSV/GCT
                    + bytes([0x00, da1, 0x00])  # 响应路由 (DA1=请求 SA1 侧)
                    + bytes([0x00, 0x02, 0x00])  # 请求路由回显
                    + bytes([sid])
                    + struct.pack(">H", fins_cmd)
                    + struct.pack(">H", 0)  # 端结码 0
                )
                if fins_cmd == fins_codec.CMD_MEMORY_AREA_READ and len(payload) >= 18:
                    (count,) = struct.unpack_from(">H", payload, 16)
                    fins += b"".join(struct.pack(">H", 0x1000 + i) for i in range(count))
                writer.write(fins_codec.build_tcp_frame(fins_codec.TCP_CMD_EXCHANGE, fins))
                await writer.drain()
            else:
                return  # 未知 TCP 命令: 断开 (垃圾流量容错)


class FakeMelsecServer(_FakeServerBase):
    """最小 MC/3E binary 设备: 0401 读回端结码 0 + 数据 (0x2000+i)。"""

    kind = "melsec"

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            head = await reader.readexactly(mc_codec.FRAME_HEADER_LEN)
            (data_len,) = struct.unpack_from("<H", head, 7)
            if data_len < 2:
                return  # 垃圾流量容错 (S7 TPKT 探测: 头部字节被当数据长解析为 0)
            data = await reader.readexactly(data_len - 2)  # 去掉定时器 2B
            if len(data) < 10:
                return  # 垃圾流量容错: 数据区不足以容纳 0401 读请求
            code = data[7]
            (count,) = struct.unpack_from("<H", data, 8)
            # 位软元件 (X/Y/B/M) 按字读: 响应字数 = ceil(count/16)
            words = (count + 15) // 16 if code in (0x9C, 0x9D, 0xA0, 0x90) else count
            resp_data = struct.pack("<H", 0)  # 端结码 0
            resp_data += b"".join(struct.pack("<H", 0x2000 + i) for i in range(words))
            resp_head = (
                mc_codec.RESPONSE_SUBHEADER_BYTES
                + head[2:7]  # 回显 网络/PC/I/O/站号
                + struct.pack("<H", len(resp_data))
            )
            writer.write(resp_head + resp_data)
            await writer.drain()


class FakeEchoServer(_FakeServerBase):
    """未知回显服务: 收到什么回什么, 无任何协议指纹。"""

    kind = "echo"

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                return  # EOF: 对端已关
            writer.write(chunk)
            await writer.drain()


_FAKE_KINDS: dict[str, type[_FakeServerBase]] = {
    cls.kind: cls
    for cls in (FakeModbusServer, FakeFinsServer, FakeMelsecServer, FakeEchoServer)
}


def build_fake(spec: dict) -> _FakeServerBase:
    """按 corpus 的 fake 描述构造实例 (不启动)。"""
    kind = spec.get("kind")
    cls = _FAKE_KINDS.get(kind)
    if cls is None:
        raise ValueError(f"unknown fake kind {kind!r}; known: {sorted(_FAKE_KINDS)}")
    kwargs: dict = {"port": int(spec.get("port", 0))}
    if kind == "modbus" and "preset" in spec:
        kwargs["preset"] = int(spec["preset"])
    return cls(**kwargs)


async def start_fake(spec: dict) -> tuple[_FakeServerBase, str, int]:
    """启动 fake 并归属探测, 返回 (fake, host, port)。

    端口策略: spec.port 为首选端口; required_port=true 时端口是条目语义
    的一部分 (如"modbus 起在 Modbus 先验端口"), 占用即抛 PortUnavailable;
    否则首选端口不可用自动回退系统分配 (port=0)。归属探测失败同样视为
    端口不可用 (Windows 通配监听 shadow 具体地址 bind 的场景)。
    """
    required = bool(spec.get("required_port", False))
    preferred = int(spec.get("port", 0))
    candidates = [preferred] if preferred else []
    if not required:
        candidates.append(0)
    errors: list[str] = []
    for port in candidates:
        fake = build_fake({**spec, "port": port})
        try:
            host, bound = await fake.start()
            await fake.wait_connection()
            return fake, host, bound
        except (OSError, TimeoutError) as exc:
            errors.append(f"port {port}: {type(exc).__name__}: {exc}")
            await fake.stop()
    raise PortUnavailable(
        f"cannot stage {spec.get('kind')!r} fake (preferred port {preferred}): "
        + "; ".join(errors)
    )
