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
    """probe_device 输出: 连通性探测 + 四类失败归因。

    reachable 语义 = 传输层可达 (TCP 已建立)。设备回异常响应
    (exception_response) 说明设备在线且协议栈正常, 此时 reachable=True,
    failure_class/exception_code 给出应用层异常 —— 分层归因的锚点。
    reachable=True 且 failure_class=None 表示可正常交换数据。
    """

    reachable: bool
    failure_class: FailureClass | None = None
    exception_code: int | None = None
    layer_hint: LayerHint = "application"
    identity: dict | None = None  # 设备身份 (enip ListIdentity: vendor/product 等)


class ReadResult(BaseModel):
    """plc_read 输出。raw_registers 为寄存器原始 16 位值; interpreted 为按
    datatype/byteorder 解释后的值。request_frame 保留 hex 便于人工核对。
    address: 整数地址 (modbus/fins/melsec/s7) 或 tag 名字符串 (enip)。"""

    target: Target
    address: int | str
    request_frame: str
    raw_registers: list[int]
    interpreted: Any = None
    interpretations: dict[str, Any] | None = None
    elapsed_ms: int


class RawExchange(BaseModel):
    """send_raw (M3, 闸门后注册) 的收发记录。"""

    target: Target
    sent_frame: str
    received_frame: str | None = None
    elapsed_ms: int


class Candidate(BaseModel):
    """诊断候选结论 (D4): 由确定性规则从观测证据推导, 不含自然语言生成
    (HANDOFF 红线 3 —— kb.yaml 的文案是预先审定的静态文本)。

    confidence 取 0-1; 规则命中强度决定取值 (精确码命中 > 关键字命中)。
    """

    symptom: str
    root_cause: str
    evidence: list[str] = []
    confidence: float
    suggested_action: str
    next_tools: list[str] = []


class DiagnosticReport(BaseModel):
    """诊断引擎 (D4) 的结构化输出: 按置信度降序的候选结论列表。

    observations 汇总本次诊断使用的原始观测 (probe 结果/解析错误/校验
    失败项), 供 Agent 复核推理链; 空候选 = 知识库未覆盖, 如实返回空。
    """

    candidates: list[Candidate] = []
    next_tools: list[str] = []
    observations: list[str] = []


class PcapFrame(BaseModel):
    """parse_pcap 输出的单帧。完整帧带 parse_auto 结果; 抓包尾部半帧
    标 partial (截断是诊断信息, 不静默丢弃)。"""

    frame_hex: str
    partial: bool = False
    parsed: ParseResult | None = None


class PcapFlow(BaseModel):
    """parse_pcap 输出的单条 TCP 流: 流向标识 + 双向帧序列。"""

    flow: str
    frames: list[PcapFrame] = []


# ---------------------------------------------------------------- v0.6.1 稳定化:
# 以下模型把此前返回裸 dict 的工具收编为建模返回。铁律 = wire 键集合与值语义
# 与建模前逐键一致 (tests/test_tool_shapes.py 黄金键集合锁定); extra="forbid"
# 让构造期就对不上键的漂移直接报错, 而不是静默丢键。


class _Frozen(BaseModel):
    """建模返回的公共基座: 多余键禁止 (黄金锁)。"""

    model_config = {"extra": "forbid"}


class WriteResult(_Frozen):
    """plc_write 输出 (五协议 adapter 统一三键)。"""

    request_frame: str
    response_frame: str
    elapsed_ms: int


class BrowseChild(BaseModel):
    """plc_browse children 的单条子节点。"""

    model_config = {"extra": "forbid"}

    node_id: str
    display_name: str | None = None
    node_class: str


class BrowseResult(_Frozen):
    """plc_browse 输出: 一层子节点 + 预算截断计数。"""

    node: str
    children: list[BrowseChild] = []
    total: int
    shown: int
    truncated: bool


class FrameRecord(BaseModel):
    """get_listener_frames / get_proxy_frames 共用的单帧记录。"""

    model_config = {"extra": "forbid"}

    ts: str
    direction: str
    peer: str
    frame_hex: str


class ListenerStartResult(_Frozen):
    """start_listener 输出。"""

    status: str
    protocol: str
    host: str
    port: int
    mode: str
    faults: list[str] = []
    recorded: int


class ListenerStopResult(_Frozen):
    """stop_listener 输出: 收帧统计。"""

    status: str
    port: int
    mode: str
    recorded: int
    sent: int


class ProxyStartResult(_Frozen):
    """start_proxy 输出。"""

    status: str
    protocol: str
    listen_port: int
    target: str
    recorded: int
    hint: str


class ProxyStopResult(_Frozen):
    """stop_proxy 输出: 双向录制统计。"""

    status: str
    port: int
    target: str
    recorded: int
    c2s: int
    s2c: int


class ListProtocolsResult(_Frozen):
    """list_protocols 输出: 外层三键锁定; protocols 内条目保持自由形态
    dict (meta 条件键"缺键而非 null"——建模会把缺键变 null, wire 即变)。"""

    protocols: dict[str, dict[str, Any]]
    allow_write: bool
    hint: str


