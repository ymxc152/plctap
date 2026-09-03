"""协议适配器接口与注册表 (ARCHITECTURE.md 第 6 节)。

新协议 = 新目录 (protocols/<name>/) + register() 登记, server.py 无需改动
(插件式扩展点)。codec 纯函数挂在适配器类的模块上, 不进入本 ABC。
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Callable, ClassVar, TypeVar

from plctap.conn.manager import ConnectionKey, ConnectionPool
from plctap.config import PlctapConfig
from plctap.models import (
    ByteOrder,
    ProbeResult,
    RawExchange,
    ReadResult,
    Target,
)

T = TypeVar("T", bound="ProtocolAdapter")


class ProtocolAdapter(ABC):
    """工业协议层适配器: v1 只做 Client/主站 (ARCHITECTURE.md 第 9 节)。

    子类职责: 网络收发 + 会话细节 (如 FINS/TCP 节点号握手) 全部封装在
    适配器内部 (D1); 帧的构造/解析一律调用对应 codec 纯函数 (D2)。
    """

    name: ClassVar[str]

    def __init__(self, pool: ConnectionPool, config: PlctapConfig) -> None:
        self.pool = pool
        self.config = config

    def key_for(self, target: Target) -> ConnectionKey:
        return ConnectionKey(
            protocol=self.name, host=target.host, port=target.port, unit=target.unit
        )

    def timeout(self, timeout_ms: int | None) -> float:
        """单次 I/O 超时秒数; 所有 socket 操作必须经 asyncio.wait_for (D3)。"""
        return (timeout_ms if timeout_ms is not None else self.config.default_timeout_ms) / 1000.0

    @abstractmethod
    async def probe(self, target: Target) -> ProbeResult:
        """连接测试 + 失败四分类 (PLAN.md 第 3 节)。"""

    @abstractmethod
    async def read(
        self,
        target: Target,
        address: int,
        count: int,
        datatype: str | None = None,
        byteorder: ByteOrder = "big",
        timeout_ms: int | None = None,
    ) -> ReadResult:
        """读数据点。count 语义由适配器定义 (Modbus: 寄存器个数)。"""

    async def write(
        self,
        target: Target,
        address: int,
        values: list[int],
        *,
        on_frame: "Callable[[str], None] | None" = None,
        point_type: str = "register",
        timeout_ms: int | None = None,
    ) -> dict:
        """写单个数据点, 返回 {"request_frame", "response_frame", "elapsed_ms"}。

        on_frame 在帧构建后、发送前被调用 (审计红线 2: 失败也留痕)。
        point_type 语义由适配器定义 (Modbus: "coil"=fc05 / "register"=fc06)。
        """
        raise NotImplementedError(f"{self.name} write not implemented yet (M3)")

    @abstractmethod
    async def send_raw(
        self, target: Target, frame_hex: str, timeout_ms: int | None = None
    ) -> RawExchange:
        """发送原始帧并等待一帧响应 (M3, 闸门后注册)。"""


_REGISTRY: dict[str, type[ProtocolAdapter]] = {}


def register_adapter(cls: type[T]) -> type[T]:
    """类装饰器: 登记适配器实现。"""
    _REGISTRY[cls.name] = cls
    return cls


def adapter_for(name: str) -> type[ProtocolAdapter]:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise KeyError(f"unknown protocol {name!r}; known: {known}") from None


def known_protocols() -> list[str]:
    return sorted(_REGISTRY)


async def recv_exact(
    reader: asyncio.StreamReader, n: int, timeout: float
) -> bytes:
    """定长读取, 统一包 wait_for 超时 (D3)。EOF 抛 IncompleteReadError。"""
    return await asyncio.wait_for(reader.readexactly(n), timeout)

