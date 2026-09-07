# 新增工业协议接入指南

本文档描述向 plctap 添加新工业协议的完整步骤。目标: **只新建文件夹, 不改已有代码**。

## 前置条件

- 理解目标协议的帧结构（请求/响应格式、地址模型、数据类型）
- 能获取或构造测试帧样本

## 目录结构

```
src/plctap/protocols/<your_protocol>/
  __init__.py      # 空文件
  meta.py          # ProtocolMeta 声明（协议名/端口/参数说明）
  codec.py         # 纯函数: 帧构造/解析/校验（无网络 I/O）
  adapter.py       # 网络适配器: probe / read / write / send_raw
```

```
src/plctap/diag/kb/<your_protocol>.yaml   # 该协议的诊断规则
tests/golden/<your_protocol>/             # 金标帧测试数据（可选但推荐）
```

## Step 1: meta.py

声明协议元数据，`list_protocols` 工具会原样返回给 Agent:

```python
"""<Your Protocol> 协议元数据。"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="your_protocol",
    default_port=1234,
    port_hints=[1234, 1235],
    addressing_model="register",  # "register" | "memory_area" | "device" | "tag"
    summary="一句话描述协议和适用设备",
    data_types=["uint16", "int16", "float32"],
    vendor_hints=["品牌A", "品牌B"],
    read_options={
        "your_param": "参数说明 (默认值)",
    },
)
```

`vendor_hints` 和 `port_hints` 帮助 Agent 从用户描述推断协议。
`read_options` 告诉 Agent `plc_read` 的 `options` 字典接受哪些键。

## Step 2: codec.py

纯函数，不依赖网络。必须实现:

```python
def build_read_request(...) -> bytes:
    """构造读请求帧。"""

def parse_response(frame: bytes) -> ParseResult:
    """结构化解析一帧（成功或失败都不抛异常）。"""

def validate_frame(frame: bytes, direction: str) -> list:
    """对帧跑规范校验清单，返回 list[CheckResult]。"""
```

帧解析规则:
- 解析失败不抛异常，而是在 `ParseResult.errors` 里记录原因
- 每个 `Field` 带 `byte_offset` 和 `raw_hex` 证据
- 异常响应帧单独处理（不能当作正常帧解析后报一堆字段错）

## Step 3: adapter.py

继承 `ProtocolAdapter`，注册到 registry:

```python
from plctap.protocols.base import (
    ProtocolAdapter, ProtocolError, recv_exact, register_adapter,
    locked_exchange, ProtocolMeta,
)
from plctap.protocols.your_protocol import codec
from plctap.protocols.your_protocol.meta import META


@register_adapter
class YourAdapter(ProtocolAdapter):
    name = "your_protocol"
    meta = META

    async def probe(self, target) -> ProbeResult:
        """连接测试 + 失败四分类。"""

    async def read(self, target, address, count, *,
                   datatype=None, byteorder="big",
                   timeout_ms=None, **options) -> ReadResult:
        """读数据。options 里的键由 meta.read_options 声明。"""

    async def send_raw(self, target, frame_hex, timeout_ms=None) -> RawExchange:
        """发送原始帧并等待响应。"""
```

注意事项:
- probe 刻意不走连接池: 一次性连接、即用即关
- `locked_exchange()` 封装了"目标级锁内一次请求-响应"的通用逻辑
- 超时统一包装为 `ProtocolError`，子类化以区分异常类型
- 写操作在 `write()` 中实现，server 层的写闸门自动控制
- **write() 必须声明 `on_frame` 参数并在请求帧构建后、任何网络动作前调用
  `on_frame(request.hex())`** —— 这是审计日志 (D5 红线: 发送前留痕, 失败也留)
  的挂钩点；漏调意味着该协议的写操作完全绕过审计 (s7 曾踩此坑, v0.5.5 修复)

## Step 4: kb.yaml

```
src/plctap/diag/kb/your_protocol.yaml
```

格式与现有 modbus.yaml 一致:

```yaml
entries:
  - id: your_protocol_exc01
    protocol: your_protocol
    match: { exception_code: [1] }
    candidate:
      symptom: 设备拒绝该功能码
      root_cause: 具体原因
      suggested_action: 建议操作
      confidence: 0.95
      next_tools: [plc_read]
```

启动时自动扫描 `kb/` 目录加载，无需改 engine.py。

## Step 5: 测试

最少要求:
- codec 纯函数单测（构造 + 解析 + 校验，含异常帧）
- adapter 冒烟测试（可用 mock server 或跳过网络）

推荐: 在 `tests/golden/your_protocol/` 放金标帧数据，用共享测试框架跑。

## Step 6: 注册 import

在 `src/plctap/server.py` 的 import 区加一行:

```python
from plctap.protocols.your_protocol.adapter import YourAdapter  # noqa: F401
```

> 注: 当前版本需要手动 import。后续版本会改为目录扫描自动发现。

## 验证清单

- [ ] `pytest tests/ -q` 全绿
- [ ] 启动 server 后 `list_protocols` 返回新协议的完整元数据
- [ ] `probe_device(protocol="your_protocol", ...)` 能正确探测
- [ ] `plc_read(protocol="your_protocol", ...)` 能正确读取
- [ ] `parse_frame(protocol="your_protocol", ...)` 能正确解析
- [ ] `diagnose(protocol="your_protocol", ...)` 能命中 KB 条目
