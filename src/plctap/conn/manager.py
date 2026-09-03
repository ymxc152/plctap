"""连接池 + 目标级互斥锁 (ARCHITECTURE.md D1)。

设计要点:
- 工具无状态, 每次携带 host/port; 池 key = (protocol, host, port, unit)。
  unit 进入 key 是因为同一 IP:PORT 上不同 unit id 的会话语义不同
  (Modbus 网关场景), 复用连接可能串话。
- 空闲 idle_timeout_sec 的连接由后台清扫任务关闭; 任务在首次 acquire
  时惰性启动, 进程退出由事件循环一并回收 (stdio server 生命周期即进程)。
- 每目标互斥锁: 一次请求-响应配对期间独占连接, 防止并发调用串包。
- 池上限: 活跃+空闲连接达到 max_per_target 后, 新连接标记为 ephemeral,
  用完即弃不入池 (限流而非阻塞)。
"""

from __future__ import annotations

import asyncio
import time
from typing import NamedTuple


class ConnectionKey(NamedTuple):
    """连接池 key (D1): (protocol, host, port, unit)。"""

    protocol: str
    host: str
    port: int
    unit: int

    @property
    def target(self) -> str:
        """人可读的目标标识, 用于审计与错误信息。"""
        return f"{self.protocol}://{self.host}:{self.port} unit={self.unit}"


class PooledConnection:
    """池中一条 TCP 连接。ephemeral=True 的连接用完即关, 不回池。"""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        key: ConnectionKey,
        ephemeral: bool = False,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.key = key
        self.ephemeral = ephemeral
        self.last_used = time.monotonic()
        # 协议适配器的每连接会话状态 (如 FINS/TCP 已完成的节点握手);
        # 连接复用时状态随连接保留, 连接销毁即作废
        self.metadata: dict[str, object] = {}

    @property
    def closed(self) -> bool:
        return self.writer.is_closing()

    def close(self) -> None:
        if not self.writer.is_closing():
            self.writer.close()


class ConnectionPool:
    def __init__(
        self,
        idle_timeout_sec: float = 30.0,
        max_per_target: int = 2,
        sweep_interval_sec: float = 5.0,
    ) -> None:
        self.idle_timeout_sec = idle_timeout_sec
        self.max_per_target = max(1, max_per_target)
        self.sweep_interval_sec = sweep_interval_sec
        self._idle: dict[ConnectionKey, list[PooledConnection]] = {}
        self._active: dict[ConnectionKey, int] = {}
        self._locks: dict[ConnectionKey, asyncio.Lock] = {}
        self._sweeper: asyncio.Task[None] | None = None

    def lock_for(self, key: ConnectionKey) -> asyncio.Lock:
        """目标级互斥锁 (D1): 覆盖整个请求-响应配对, 防并发串包。"""
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    async def acquire(
        self,
        key: ConnectionKey,
        connect_timeout: float,
    ) -> PooledConnection:
        """取一条可用连接: 优先复用空闲连接, 否则新建。新建失败向上抛
        ConnectionRefusedError / TimeoutError 等, 由适配器做失败分类。"""
        # 1) 复用空闲连接 (跳过已被对端关闭的)
        idle = self._idle.get(key)
        while idle:
            conn = idle.pop()
            if not conn.closed:
                self._active[key] = self._active.get(key, 0) + 1
                conn.last_used = time.monotonic()
                return conn
            conn.close()  # 确保 socket 资源释放

        # 2) 新建; 达到池上限则建 ephemeral 连接 (用完即弃)
        ephemeral = self._active.get(key, 0) >= self.max_per_target
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(key.host, key.port), connect_timeout
        )
        conn = PooledConnection(reader, writer, key, ephemeral=ephemeral)
        self._active[key] = self._active.get(key, 0) + 1
        self._ensure_sweeper()
        return conn

    def release(self, conn: PooledConnection, *, healthy: bool = True) -> None:
        """归还连接。healthy=False (协议层出错/流可能失步) 时直接丢弃。"""
        self._active[conn.key] = max(0, self._active.get(conn.key, 1) - 1)
        if not healthy or conn.ephemeral or conn.closed:
            conn.close()
            return
        conn.last_used = time.monotonic()
        self._idle.setdefault(conn.key, []).append(conn)

    def discard(self, conn: PooledConnection) -> None:
        """异常路径丢弃连接 (release 的别名, 语义化使用)。"""
        self.release(conn, healthy=False)

    async def close_all(self) -> None:
        """关闭全部空闲连接并停掉清扫任务 (测试收尾用)。"""
        if self._sweeper is not None:
            self._sweeper.cancel()
            try:
                await self._sweeper
            except asyncio.CancelledError:
                pass
            self._sweeper = None
        for idle in self._idle.values():
            for conn in idle:
                conn.close()
        self._idle.clear()

    def _ensure_sweeper(self) -> None:
        """清扫任务惰性启动: 首次成功建连时才创建, 之后常驻。"""
        if self._sweeper is not None and not self._sweeper.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._sweeper = loop.create_task(self._sweep_loop())

    async def _sweep_loop(self) -> None:
        while True:
            await asyncio.sleep(self.sweep_interval_sec)
            now = time.monotonic()
            for key, idle in list(self._idle.items()):  # 快照迭代: release() 可能并发改字典
                keep: list[PooledConnection] = []
                for conn in idle:
                    if now - conn.last_used > self.idle_timeout_sec or conn.closed:
                        conn.close()
                    else:
                        keep.append(conn)
                if keep:
                    self._idle[key] = keep
                else:
                    self._idle.pop(key, None)

