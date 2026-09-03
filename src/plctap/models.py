"""核心数据模型 (ARCHITECTURE.md 第 4 节)。"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

Direction = Literal["req", "resp"]

FailureClass = Literal[
    "connection_refused",
    "timeout",
    "connected_but_no_reply",
    "exception_response",
]

LayerHint = Literal["connectivity", "protocol", "application"]

# Modbus float32 字节序选项 (决策见 protocols/modbus/codec.py interpret_registers)
ByteOrder = Literal["big", "little"]


class Target(BaseModel):
    """目标设备标识, 同时是连接池 key 的组成部分 (D1)。"""

    protocol: str
    host: str
    port: int
    unit: int = 1


class FrameField(BaseModel):
    """解析出的单个报文字段。命名用 FrameField 而非 Field, 避免与
    pydantic.Field 混淆 (ARCHITECTURE.md 模型图中的 Field 即本模型)。"""

    name: str
    value: Any  # int | str | list[int] | ...
    raw_hex: str
    byte_offset: int
    note: str = ""


class ParseResult(BaseModel):
    """codec.parse 的输出。errors 汇总所有结构/交叉校验问题; valid = not errors。"""

    protocol: str
    direction: Direction
    fields: list[FrameField] = []
    valid: bool = True
    errors: list[str] = []


class CheckResult(BaseModel):
    """validate_frame 校验清单的单项结果。"""

    name: str
    passed: bool
    detail: str = ""


class ProbeResult(BaseModel):
    """probe_device 输出: 连通性探测 + 四类失败归因 (PLAN.md 第 3 节)。

    reachable=True 时 failure_class 为 None, layer_hint 表示最深到达的层。
    """

    reachable: bool
    failure_class: FailureClass | None = None
    exception_code: int | None = None
    layer_hint: LayerHint = "application"


class ReadResult(BaseModel):
    """plc_read 输出。raw_registers 为寄存器原始 16 位值; interpreted 为按
    datatype/byteorder 解释后的值。request_frame 保留 hex 便于人工核对。"""

    target: Target
    address: int
    request_frame: str
    raw_registers: list[int]
    interpreted: Any = None
    elapsed_ms: int


class RawExchange(BaseModel):
    """send_raw (M3, 闸门后注册) 的收发记录。"""

    target: Target
    sent_frame: str
    received_frame: str | None = None
    elapsed_ms: int


class DiagnosticReport(BaseModel):
    """诊断引擎 (M2, D4) 的结构化输出, 占位定义。candidates 元素:
    {symptom, evidence[], confidence, suggested_action}。"""

    candidates: list[dict[str, Any]] = []
    next_tools: list[str] = []
