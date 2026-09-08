"""透明代理 (v0.4): 上位机 → plctap 代理 → 真实 PLC, 透传同时按协议分帧录制。

与钓鱼监听共享 streams.py 分帧设施。代理是诊断设施不是转发器产品:
每一帧在透传时落入环形缓冲, 拿到帧后可走 parse_frame / diagnose 做在线
分析 —— 现场联调不用再挂 Wireshark。S7 (TPKT) 分帧不在 streams 支持内,
代理同监听器口径只做 modbus / fins / melsec。

字节流语义: 按完整帧转发 (半帧暂存缓冲等对端续上); 若某方向持续凑不出
完整帧 (协议不匹配/非预期流量), 缓冲超过上限后转盲转发 —— 录制失败不
阻断通信。
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from plctap import streams

_PROXY_FRAME_LIMIT = 1000  # 环形上限, 同监听器
_BLIND_FLUSH_BYTES = 1 << 20  # 单方向凑不出帧的盲转阈值 (1MB)


@dataclass
class _Proxy:
    protocol: str
    listen_port: int  # 实际监听端口
    target_host: str
    target_port: int
    server: asyncio.AbstractServer
    frames: list[dict] = field(default_factory=list)
    tasks: set[asyncio.Task] = field(default_factory=set)  # 每客户端连接一个 pump task
    c2s: int = 0  # 上位机 → PLC 帧数
    s2c: int = 0  # PLC → 上位机 帧数
    started_at: float = field(default_factory=time.time)


class ProxyRegistry:
    """listen_port -> proxy。所有状态活在进程内 (与监听器同口径)。"""

    def __init__(self) -> None:
        self._proxies: dict[int, _Proxy] = {}

    async def start(
        self,
        protocol: str,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
        idle_timeout_sec: int = 120,
    ) -> dict:
        if protocol not in streams.FRAME_HEADER_LEN:
            raise ValueError(
                f"protocol must be one of {tuple(streams.FRAME_HEADER_LEN)}, got {protocol!r} "
                "(S7 TPKT 分帧暂不支持)"
            )
        if not 0 <= listen_port <= 65535:
            raise ValueError(f"listen_port {listen_port} out of range 0-65535")
        if not 0 <= target_port <= 65535:
            raise ValueError(f"target_port {target_port} out of range 0-65535")
        if not idle_timeout_sec > 0:
            raise ValueError(f"idle_timeout_sec must be > 0, got {idle_timeout_sec}")
        if listen_port and listen_port in self._proxies:
            raise ValueError(f"proxy already running on port {listen_port}")

        # holder 规避竞态: start_server 返回前连接理论上已可到达, 而 _Proxy
        # 又要等 actual_port 才能构造 —— 回调经 holder 延迟取对象
        holder: dict[str, _Proxy] = {}
        idle_timeout = float(idle_timeout_sec)

        def _spawn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            t = asyncio.ensure_future(self._pump_pair(holder["pr"], reader, writer, idle_timeout))
            pr = holder["pr"]
            pr.tasks.add(t)
            t.add_done_callback(pr.tasks.discard)

        server = await asyncio.start_server(_spawn, listen_host, listen_port)
        actual_port = server.sockets[0].getsockname()[1]
        pr = _Proxy(
            protocol=protocol,
            listen_port=actual_port,
            target_host=target_host,
            target_port=target_port,
            server=server,
        )
        holder["pr"] = pr
        self._proxies[actual_port] = pr
        return {
            "status": "proxying",
            "protocol": protocol,
            "listen_port": actual_port,
            "target": f"{target_host}:{target_port}",
            "recorded": 0,
            "hint": "上位机改连本代理端口; get_proxy_frames 取透传帧",
        }

    async def stop(self, port: int) -> dict:
        pr = self._proxies.pop(port, None)
        if pr is None:
            raise ValueError(f"no proxy on port {port}")
        pr.server.close()
        for t in list(pr.tasks):
            t.cancel()
        await asyncio.gather(*pr.tasks, return_exceptions=True)
        pr.tasks.clear()
        await pr.server.wait_closed()
        return {
            "status": "stopped",
            "port": port,
            "target": f"{pr.target_host}:{pr.target_port}",
            "recorded": len(pr.frames),
            "c2s": pr.c2s,
            "s2c": pr.s2c,
        }

    def frames(self, port: int, limit: int = 100) -> list[dict]:
        pr = self._proxies.get(port)
        if pr is None:
            raise ValueError(f"no proxy on port {port}")
        # 语义同监听器: 取最新 limit 条; limit<=0 显式返回空 ([-0:] 即全量的陷阱)
        n = min(max(int(limit), 0), _PROXY_FRAME_LIMIT)
        return list(pr.frames[-n:]) if n else []

    def active_ports(self) -> list[int]:
        return sorted(self._proxies)

    # ------------------------------------------------------------ 连接处理

    async def _pump_pair(
        self, pr: _Proxy, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter, timeout: float
    ) -> None:
        """一条客户端连接 = 上游建连 + 双向 pump; 任一侧断开/超时则两侧同断。"""
        peer = str(client_w.get_extra_info("peername"))
        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(pr.target_host, pr.target_port), timeout
            )
        except (OSError, ConnectionError, TimeoutError):
            client_w.close()
            return
        try:
            await asyncio.gather(
                self._pump_dir(pr, client_r, up_w, "c2s", peer, timeout),
                self._pump_dir(pr, up_r, client_w, "s2c", peer, timeout),
            )
        finally:
            client_w.close()
            up_w.close()

    async def _pump_dir(
        self,
        pr: _Proxy,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        peer: str,
        timeout: float,
    ) -> None:
        """单方向: 读 → 按协议分帧记录 → 逐帧透传; 凑不出帧超阈值后转盲转发。"""
        buf = b""
        blind = False
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout)
            except TimeoutError:
                return  # 空闲超时 (与监听器同口径)
            except (OSError, ConnectionError):
                return
            if not chunk:
                return  # EOF: 对端已关
            if blind:
                writer.write(chunk)
                try:
                    await writer.drain()
                except (OSError, ConnectionError):
                    return
                continue
            buf += chunk
            while True:
                n = streams.try_frame_len(pr.protocol, buf)
                if n is None or n == 0:
                    break  # 凑不齐 (None) / 长度字段畸形 (0): 交给盲转判定
                frame, buf = buf[:n], buf[n:]
                pr.frames.append(
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "direction": direction,
                        "peer": peer,
                        "frame_hex": frame.hex(),
                    }
                )
                if direction == "c2s":
                    pr.c2s += 1
                else:
                    pr.s2c += 1
                writer.write(frame)
                try:
                    await writer.drain()
                except (OSError, ConnectionError):
                    return
            if len(buf) > _BLIND_FLUSH_BYTES:
                # 协议不匹配/非预期流量: 冲掉缓冲转盲转发, 录制失败不阻断通信
                writer.write(buf)
                try:
                    await writer.drain()
                except (OSError, ConnectionError):
                    return
                buf = b""
                blind = True
            if len(pr.frames) > _PROXY_FRAME_LIMIT:
                del pr.frames[: len(pr.frames) - _PROXY_FRAME_LIMIT]
