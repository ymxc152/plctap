# plctap — Agent-PLC MCP Server 架构设计（ARCHITECTURE.md）

> 配合 PLAN.md v5 与 BUILD.md 使用｜2026-09-03 初稿，2026-09-07 对齐 v0.6 八端点（含 OPC UA 连接级诊断）

## 1. 分层架构总览

```
MCP 客户端 (Claude Desktop / Codex / Cursor)
        │ MCP stdio
MCP Server (FastMCP)
  ├─ 工具注册表（按配置条件注册，写工具默认缺席）
  ├─ 安全闸门 + 审计日志(JSONL)
  ├─ 连接管理器（连接池/空闲回收/目标级锁）
  ├─ 协议适配器（插件式: modbus / modbus_rtu / fins / melsec / s7 / iec104 / enip / opcua 八端点;
  │   opcua 为会话式——asyncua 封装, 仅连接级诊断, 无 codec/帧级工具）
  ├─ 协议识别器 detect_device（_PROFILES 注册表: 扫端口 → 指纹 → 最小读验证, 全程只读）
  ├─ 主动诊断设施（透明代理 proxy.py / 钓鱼监听 listener.py, streams.py 分帧共用）
  ├─ Codec 纯函数层 (parse / validate / build)
  └─ 诊断引擎（规则引擎 + YAML 知识库, 纯确定性输出）
        │ TCP
真实 PLC / 仿真器台架
评测 harness（离线独立进程, 直连 codec, 不走 MCP）
```

## 2. 关键架构决策（ADR 摘要，D1-D5 于 2026-09-03 确认，D8-D9 随 v0.4 增补；D6/D7 见本节末）

### D1 会话模型：无状态参数 + 内部透明连接池
- 工具每次携带 host/port，不暴露 connect()/session_id
- 连接池 key = (protocol, host, port, unit)；空闲 30s 回收；池上限可配
- FINS/TCP 节点号握手等细节封装在适配器内部
- 每目标地址互斥锁，防并发写竞争
- 理由：LLM 管理 session id 极易出错（遗忘/编造/过期）

### D2 Codec 纯函数化（可测试性根基）
- parse(hex)->ParseResult、validate(frame)->CheckList、build(params)->hex 均为纯函数
- 适配器只做网络 I/O；评测/单测/故障注入只测纯函数，CI 毫秒级
- ParseResult 每字段带 byte offset 与原始 hex 片段，供 diagnose 引用证据

### D3 异步 I/O：纯 asyncio
- 适配器用 asyncio.open_connection + asyncio.wait_for 超时
- 不依赖同步协议库（pymodbus 等仅作行为对齐参考）
- 与 MCP 工具超时语义天然对齐；支持并发探测多设备

### D4 诊断引擎纯确定性
- 规则引擎 + kb.yaml，输出结构化候选: {symptom, evidence[], confidence, suggested_action}
- 不生成自然语言；叙述由 Agent + Skill 层完成
- 输出可被 Agent 用于继续调用 probe_device 验证 → 诊断→探测→确认工具链

### D5 安全闸门：注册层控制 + 全量审计（方案C，已确认）
- allow_write=false 时写类工具根本不注册（Agent 不可见）
- 开启后每次写/发送写 JSONL 审计: {ts, tool, target, frame_hex, caller}
- 配套 MCP 审批弹窗（config.toml: default_tools_approval_mode / per-tool approval_mode）

### D8 协议自动识别注册表（v0.4 增补）
- detect 的 _PROFILES 注册表：新协议接入 = adapter register + 注册表加一条，识别逻辑零改动
- 端口先验只影响同级候选排序、不参与置信度——44818 被 MELSEC SLMP 与 EtherNet/IP 撞号，先验显式置 None，靠响应指纹消歧
- 全程只发握手帧 + 最小读帧（只读）；"识别 ≠ 可访问"（如 S7 PUT/GET 关闭时识别成功但读仍失败）

### D9 服务端主动诊断设施（v0.4 增补）
- 透明代理与钓鱼监听共享 streams.py 分帧纯函数（与 parse_pcap 同源），只透传/录制不改写帧
- 监听三档 record_only / respond_normal / inject_errors（respond_scripted 留待需要时）；inject_errors 兼评测语料生成器
- 共享连接池等基础设施，codec.build/parse 反向复用——"被连接"能力不引入第二套协议栈

## 3. 目录结构

```
plctap/
├── pyproject.toml              # 入口: plctap (console script)
├── src/plctap/
│   ├── server.py               # FastMCP app + 条件注册 + 工具层校验 (_validate_address 等)
│   ├── config.py               # allow_write / 池大小 / 超时
│   ├── safety.py               # 闸门 + 审计日志 (on_frame 发送前回调)
│   ├── models.py               # ParseResult / ReadResult / DiagnosticReport / Target
│   ├── conn/manager.py         # 连接池 + 目标级锁
│   ├── proxy.py / listener.py  # 透明代理 / 钓鱼监听 (v0.4)
│   ├── streams.py              # 协议流分帧纯函数 (代理/监听/pcap 共用)
│   ├── pcap.py                 # parse_pcap: 流聚合 → 逐流协议判别 → 逐帧解析
│   └── protocols/
│       ├── base.py             # ProtocolAdapter ABC + 注册表
│       ├── auto.py             # parse_auto 方向判别 (server 与诊断引擎共用)
│       ├── detect.py           # DeviceDetector + _PROFILES 注册表 (v0.4)
│       ├── common.py
│       └── modbus/ fins/ melsec/ s7/ iec104/ enip/   # 各含 adapter.py + codec.py + meta.py
│           （modbus_rtu 与 modbus 帧级同轨，共用 codec，独立 adapter）
├── diag/
│   ├── engine.py               # 确定性规则引擎
│   └── kb/{common,s7,fins,melsec,modbus,iec104,enip}.yaml   # 故障知识库 (按协议拆分)
├── skill/SKILL.md              # 方法论指令层
├── eval/
│   ├── corpus/                 # 八档评测集 (yaml, 全合成帧)
│   ├── benchmark.py            # 工具模式打分
│   └── baseline.py             # 裸模型基线 runner
├── tests/                      # 纯函数单测 + MCP 冒烟 + tests/e2e 六方交叉验证
└── README.md
```

## 4. 核心数据模型（Pydantic）

```python
class ParseResult(BaseModel):
    protocol: str
    direction: "req" | "resp"
    fields: list[Field]          # name, value, raw_hex, byte_offset, note
    valid: bool

class ReadResult(BaseModel):
    target: Target               # protocol/host/port/unit
    request_frame: str           # hex, 便于调试
    raw_registers: list[int]
    interpreted: Any             # 按 datatype/byteorder 解释
    elapsed_ms: int

class ProbeResult(BaseModel):
    reachable: bool
    failure_class: "connection_refused" | "timeout" | \
                   "connected_but_no_reply" | "exception_response" | None
    exception_code: int | None
    layer_hint: "connectivity" | "protocol" | "application"

class DiagnosticReport(BaseModel):
    candidates: list[Candidate]  # symptom/evidence/confidence/suggested_action
    next_tools: list[str]        # 建议Agent接下来调用的工具
```

## 5. 数据流走查

### 场景 A: "读 40001 开始 10 个寄存器"
plc_read(modbus, host, 502, addr=0, count=10, datatype=float32)
→ 连接池取/建 TCP → codec.build 请求帧 → 发送 → codec.parse 响应
→ 字节序解释 → ReadResult。一次工具调用完成。

### 场景 B: "192.168.1.10 读不到数据"
probe_device → timeout → (Skill 指引) 查网络层
端口通 → plc_read → 异常码 0x02 → diagnose 匹配 KB
→ "地址越界, 建议先确认寄存器区范围" → Agent 转述。
三层分类（连接/协议/应用）对应三条工具路径。

## 6. 协议适配器接口

```python
class ProtocolAdapter(ABC):
    async def probe(self, target) -> ProbeResult
    async def read(self, target, address, count, datatype) -> ReadResult
    async def write(self, target, address, values, options) -> WriteResult  # 闸门后注册
    async def send_raw(self, target, frame_hex) -> RawExchange
    # codec 纯函数: adapter.codec.parse / validate / build
```
新协议 = 新目录 + 注册表登记 + detect._PROFILES 加一条，server.py 不改（插件式扩展点；
接入手册见 docs/ADD_PROTOCOL.md）。两条地址/审计约束：
- address 语义按协议而异：多数为 int（S7 为字节地址、count=字节数），enip 为 tag 名字符串；
  MCP 层 schema 已放宽 int|str，由服务层 `_validate_address` 按协议校验并给出明确报错
- **write 实现必须在构建请求帧后、任何网络动作前回调 `on_frame(request.hex())`**——
  漏调即写操作绕过审计（D5 红线；s7 曾踩坑，ADD_PROTOCOL.md 有防复发条款）

## 7. 配置与部署

```toml
# ~/.codex/config.toml 或 claude_desktop_config.json
[plctap]
allow_write = false          # 默认
pool_max_per_target = 2
idle_timeout_sec = 30
default_timeout_ms = 2000
audit_log = "~/.plctap/audit.jsonl"
```
分发: pipx/uvx 安装；Claude Desktop / Codex 各给一段配置样例；后续可加 streamable_http 远程模式。

## 8. 演进路线
- v0.1 (M1-M3): Modbus/FINS/MELSEC 读写闭环 + 诊断引擎 + 五档评测基线 + GitHub/PyPI v0.1.0
- v0.2: S7comm + MELSEC 全 4 帧格式（pymcprotocol 字节级对照 + snap7 交叉验证）+ ProtocolMeta 自描述
- v0.3: 写能力补全（FINS 0102 / MELSEC 1401）+ parse_pcap 逐流判别 + 四字序解释 + 跨厂商 e2e 进 CI
- v0.4: 主动诊断旗舰——detect_device 协议识别 / 透明代理 / 监听 inject_errors 故障注入档
- v0.5（现态）: Modbus RTU over TCP + IEC 60870-5-104 + EtherNet/IP (CIP)；发布 wheel 真实台架验收方法学；guard-main 发布闸门
- v0.6（规划）: 产品化收官——hypothesis 模糊测试 / 工具输出 token 预算测试 / 脱敏诊断案例 / demo 扩幕 / OPC UA 轻量接入（可选）/ 裸模型基线复跑（详见 PLAN.md 第 4 节）
- v2（候选）: 串口原生 RTU；明确不做：Web 管理界面 / server 内 LLM / DNP3 / BACnet / Profinet 二层栈

### D6 评测设计：分层难度 + 同模型双跑（已确认）
- 五档难度起步: 单帧ModbusTCP / RTU CRC / FINS·MELSEC / 批量日志 / 主动探测；v0.5 起扩至八档（+自动识别 / iec104 / enip，后三档需台架交互、无裸问答基线）
- 同一批帧: 裸模型问答 vs 挂MCP工具, 同一模型消融, 分层报准确率
- 不做竞品准确率对比; README 放功能覆盖对比表即可

### D7 I/O 模型: 纯 asyncio（已确认, 随技术栈D3=Python+FastMCP）
## 9. 工业协议层角色定位（2026-09-03 补充）

两个"server"概念区分：
- MCP 协议层: 永远是 Server（向 Claude/Codex 暴露工具）
- 工业协议层: v1 只做 Client/主站（主动连 PLC）

"被连接"能力的演进（不做通用模拟器, 那是 ProtoForge 的地盘, 用集成代替重写）:
- v1   : 仅 Client/主站
- v1.1 : 服务端诊断套件(共享监听基础设施, codec.parse/build 反向复用):
           start_proxy  诊断代理: 上位机→代理→真实PLC 透明转发+录制
                        → 排查"上位机说没回 / PLC 说没发"扯皮场景
           start_listener 钓鱼模式(实习真实痛点背书):
                        待测设备只能当client时, 立假server钓出其帧行为
                        mode(已实现): record_only / respond_normal / inject_errors
                        (respond_scripted 可编程回帧留待需要时)
                        → 捕获畸形握手/错误字节序/重发风暴; inject_errors 兼评测语料生成
- 永不做: 独立完整从站模拟器；ProtoForge 作为开发/测试依赖引入




