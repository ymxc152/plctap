# plctap

<!-- mcp-name: io.github.ymxc152/plctap -->

中文 | [English](README.en.md)

> Agent 的 PLC 驱动层 — 让 Claude / Codex / Cursor 直接连接、读写、诊断
> Modbus TCP / Modbus RTU over TCP / FINS / MELSEC / Siemens S7comm / IEC 60870-5-104 / EtherNet/IP (CIP) 设备的 MCP Server。

![CI](https://github.com/ymxc152/plctap/actions/workflows/ci.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/plctap)](https://pypi.org/project/plctap/)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.ymxc152%2Fplctap-blue)](https://registry.modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

![demo](docs/demo.gif)

**状态: v0.6 (协议自动识别 + 透明代理 + 故障注入监听 + 八协议端点接入 (含 OPC UA 连接级诊断), 六端点可写 (IEC 104 / OPC UA 仅读); IEC 104 经 lib60870、EtherNet/IP 经 pycomm3 官方实现交叉验证, OPC UA 为 asyncua 官方库台架自洽验证)。**

## 工具

| 层 | 工具 | 说明 |
|---|---|---|
| 连接 | `detect_device` | **协议自动识别**: 给 IP 并发探测标准端口, 按响应指纹判定协议/端口/置信度, deep 模式验证读并生成可执行的 plc_read 建议; 全程只读 |
| 连接 | `probe_device` | 连通性探测 + 四类失败分层归因 (MELSEC 支持 3E binary/ASCII 自动回退; IEC 104 为 STARTDT+TESTFR 握手探测) |
| 连接 | `plc_read` | 读数据区并按 datatype/字节序解释 (八个协议端点: modbus / modbus_rtu / fins / melsec / s7 / iec104 / enip / opcua); datatype 缺省返回 uint16/int16/float32 四种字序 (abcd/cdab/badc/dcba)/int32 多解释 (opcua 返回 UA 原生类型) |
| 连接 | `plc_browse` | 地址空间浏览: 从 node 展开一层子节点, 摸清设备数据结构后再读 (仅 OPC UA; 输出预算 200 子节点, 截断带 total/shown 计数) |
| 诊断 | `parse_frame` / `validate_frame` | 单帧结构化解析 / 规范校验清单 |
| 诊断 | `diagnose` | 规则引擎 + 故障知识库 → 结构化候选报告 |
| 诊断 | `parse_pcap` | 解析 Wireshark 导出 pcap, 逐流逐帧 (每条 TCP 流独立判别协议, 需 `uv sync --extra eval`) |
| 监听 | `start_listener` / `stop_listener` / `get_listener_frames` | 钓鱼模式: 设备只能当 client 时立假 server 收帧分析 (三档: record_only / respond_normal / inject_errors 故障注入轮转; MELSEC 回帧支持全部 4 种帧格式; IEC 104 回 STARTDT/TESTFR CON 与总召罐头帧; EtherNet/IP 回 RegisterSession CON 与读 tag 应答罐头帧) |
| 监听 | `start_proxy` / `stop_proxy` / `get_proxy_frames` | 透明代理: 上位机 → 代理 → 真实 PLC, 透传同时分帧录制双向帧, 在线联调免 Wireshark (modbus/fins/melsec) |
| 执行 | `plc_write` / `send_frame` | **默认不注册**, `PLCTAP_ALLOW_WRITE=true` 才启用 (闸门) |

全部工具带 MCP annotations hint (wire 逐键锁定于 `tests/test_tool_annotations.py`): 纯本地解析类
`readOnlyHint=true` / `openWorldHint=false`, 联网读/探测/取帧类 `readOnlyHint=true`, 监听/代理
启停为非只读状态变更 (非破坏、非幂等), 写类 `destructiveHint=true` 且默认不注册 —— 客户端可
据此判断并行安全性与调用前确认级别。

## 写能力

`PLCTAP_ALLOW_WRITE=true` 后八端点中六个可写 (modbus_rtu 与 modbus 同轨同语义; iec104 与 opcua 仅读):

| 协议 | 写语义 | options |
|---|---|---|
| Modbus | fc16 批量写寄存器 (默认) / fc05 线圈 / fc06 单寄存器 | `point_type`, `options.function_code`, `options.values` |
| S7 | 16 位字写入 DB/M/I/Q 区 | `options.area`, `options.db_number` |
| FINS | 0102 存储区写字 (CIO/W/H/A/DM/EM) | `options.area` |
| MELSEC | 1401 批量写字, 全部 4 种帧格式 | `options.device`, `options.frame_format` |
| EtherNet/IP | CIP tag 写 (0x4D); 整数默认 DINT, 浮点需显式 `options.type="REAL"` | `point_type="tag"`, `options.type` |

所有写/发送动作逐帧写入审计日志 (发送前留痕, 失败也留)。

## 协议速查

八个端点的寻址模型与常用参数 (接入前先对表; 工具内 `list_protocols` 亦可动态获取):

| 端点 | 默认端口 | 地址语义 | 常用 options |
|---|---|---|---|
| `modbus` | 502 | 寄存器地址 **0 基**, count=寄存器数 | `options.function_code`: 3=保持寄存器 (默认), 4=输入寄存器 |
| `modbus_rtu` | 网关自定义 (常见 502 / 8899) | 同 `modbus` (TCP 上跑裸 RTU 帧, 无 MBAP 头) | 同 `modbus` |
| `fins` | 9600 | 字地址, count=字数 | `options.area`: CIO/W/H/A/DM/EM (默认 DM) |
| `melsec` | 44818 (SLMP; 5007 亦常见) | 起始编号, count=点数 (位软元件按 16 点/字) | `options.device`: D/R/W=字, X/Y/B/M=位 (默认 D); `options.frame_format` 4 种 (默认 3e_binary) |
| `s7` | 102 | **字节**地址, count=**字节数** | `options.area`: DB/M/I/Q (默认 DB); `options.db_number` (默认 1); `rack`/`slot` (默认 0/1, S7-300 槽位通常 2) |
| `iec104` | 2404 (2405 亦常见) | IOA 信息对象地址, **总召收集式读**, count=连续 IOA 点数 (M_ME_NC 短浮点每点占 2 个 16 位字) | `options.ca`: 公共地址 (默认 1); `options.qoi`: 总召 QOI (默认 20 站总召) |
| `enip` | 44818 (2222 亦常见; 与 MELSEC SLMP 同端口, detect 按响应指纹区分) | **tag 名**字符串 (如 "alpha[0]"), count=元素个数 (数组 tag) | 写: `options.type`: DINT (默认) / REAL 等; 读支持 dint / bool 等 CIP 类型 |
| `opcua` | 4840 | **NodeId** 字符串 (如 "ns=2;i=5" / "ns=2;s=Demo.Double"), count=数组节点返回元素上限 (0=全部); 值按 UA 内建类型原生返回 | 仅 SecurityPolicy None (诊断场景); `plc_browse` 从 ns=0;i=85 摸地址空间; **不做帧级诊断** (parse_frame/validate_frame 显式拒绝) |

`datatype` 支持 uint16 / int16 / float32 / int32; `byteorder` 仅影响 float32 的寄存器对顺序
(big=ABCD, little=DCBA)。datatype 缺省时返回全部常见类型 × 字序的多解释, 字序存疑时直接比对。

示例调用 (客户端中按参数填写):

```text
plc_read(protocol="modbus",     host="10.0.0.10",    port=502,   address=0,          count=2,  datatype="float32", byteorder="big")
plc_read(protocol="modbus_rtu", host="192.168.1.50", port=8899,  unit=2,             address=100, count=10)
plc_read(protocol="fins",       host="10.0.0.30",    port=9600,  address=100,        count=10, options={"area": "DM"})
plc_read(protocol="melsec",     host="10.0.0.40",    port=44818, address=100,        count=10, options={"device": "D"})
plc_read(protocol="s7",         host="10.0.0.20",    port=102,   address=0,          count=4,  datatype="float32", options={"area": "DB", "db_number": 1})
plc_read(protocol="iec104",     host="10.0.0.60",    port=2404,  address=1,          count=5,  options={"ca": 1})
plc_read(protocol="enip",       host="10.0.0.70",    port=44818, address="alpha[0]", count=3,  datatype="dint")
```

`modbus` 与 `modbus_rtu` 怎么选: 网关/上位机已封装 MBAP 头 (标准 Modbus TCP) → `modbus`;
串口服务器或网关工作在 RTU 透传模式 (TCP 上是裸 RTU 帧) → `modbus_rtu`。

## 典型工作流 (现场诊断)

1. `detect_device(host=...)` — 不知道对面是什么: 并发探测标准端口, 按响应指纹判定协议/端口/置信度,
   返回可直接执行的 `plc_read` 建议 (全程只读)。
2. `probe_device(protocol, host, port)` — 连通性确认; 失败时四类分层归因
   (connection_refused / timeout / connected_but_no_reply / exception_response),
   直接告诉您该查网络路由还是查协议配置 (IEC 104 为 STARTDT+TESTFR 握手探测)。
3. `plc_read(...)` — 按「协议速查」读数, 与上位机显示或预期值比对。
4. 读数不对 / 通信故障 → 抓包帧喂 `parse_frame` / `validate_frame` 做结构化解析与规范校验;
   日志文本喂 `diagnose` 得到带证据链的结构化候选结论。
5. 要看上位机 ↔ PLC 全部交互 → `start_proxy` 透明代理 (上位机改指向代理即可, 免 Wireshark);
   设备只能当 client 主动外连 → `start_listener` 假 server 钓帧, 支持 `inject_errors`
   故障注入档做上位机容错回归。

## 快速开始

```bash
uvx plctap          # 或 pipx install plctap
```

已收录于 MCP 官方 Registry: [`io.github.ymxc152/plctap`](https://registry.modelcontextprotocol.io/)
(支持按名称检索与安装的客户端可直接发现本服务)。

### Claude Desktop 接入 (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "plctap": {
      "command": "uvx",
      "args": ["plctap"],
      "env": { "PLCTAP_ALLOW_WRITE": "false" }
    }
  }
}
```

本地开发 (仓库检出路径):

```json
{
  "mcpServers": {
    "plctap": {
      "command": "uv",
      "args": ["--directory", "C:/path/to/plctap", "run", "plctap"]
    }
  }
}
```

### Codex 接入 (`~/.codex/config.toml`)

```toml
[mcp_servers.plctap]
command = "uvx"
args = ["plctap"]

[mcp_servers.plctap.env]
PLCTAP_ALLOW_WRITE = "false"   # 写闸门默认关闭
PLCTAP_DEFAULT_TIMEOUT_MS = "2000"
```

### 配置 (环境变量, 均有默认值)

| 变量 | 默认 | 说明 |
|---|---|---|
| `PLCTAP_ALLOW_WRITE` | `false` | **写类工具默认不注册** (安全闸门) |
| `PLCTAP_POOL_MAX_PER_TARGET` | `2` | 每目标连接池上限 |
| `PLCTAP_IDLE_TIMEOUT_SEC` | `30` | 空闲连接回收秒数 |
| `PLCTAP_DEFAULT_TIMEOUT_MS` | `2000` | 网络超时 (串口网关 / 远程站点等慢链路可调大) |
| `PLCTAP_AUDIT_LOG` | `~/.plctap/audit.jsonl` | 审计日志路径 (写/发送动作逐帧留痕) |

## 安全

- 写操作默认**完全不注册**; 显式 `PLCTAP_ALLOW_WRITE=true` 才启用。
- 所有写/发送动作逐条写入 JSONL 审计日志 (`~/.plctap/audit.jsonl`, 不可关)。
- 发送类调用请配合客户端审批弹窗使用 (用户可见目标 IP 与完整帧)。
- 审计日志样例:
  `{"ts":"2026-09-04T01:20:33+0800","tool":"plc_write","target":"modbus://127.0.0.1:15020 unit=1","frame_hex":"0002000000060106000104d2","caller":"mcp"}`

## 开发

```bash
uv sync --extra eval --group e2e
uv run pytest -q   # 单测 (codec/适配器/诊断/监听) + 跨厂商 e2e + MCP 冒烟
uv run plctap      # 本地启动 stdio server
```

## 质量保障

- **569 项测试**（codec 纯函数 + 适配器（含 Modbus RTU / IEC 104 / EtherNet/IP / OPC UA）+ 诊断引擎 + 监听器 + 透明代理 + detect_device + MCP 冒烟），CI 每次推送回归。
- **跨厂商 e2e**（[tests/e2e](tests/e2e/test_cross_vendor.py)）：plctap 与 pymodbus、python-snap7、
  pymcprotocol、pypi fins、MZ Automation 官方 lib60870.NET、pycomm3（Rockwell 官方客户端库）六个第三方权威实现做真实 socket 交叉验证
  （读写闭环、读数逐值比对、钓鱼监听互通），CI 随行（`uv sync --group e2e`）；
  IEC 104 交叉验证需 .NET 8 SDK（缺省自动跳过）。OPC UA 端点为 asyncua 官方库 +
  台架自洽验证（会话协议无帧级诊断，与本节其余端点的字节级交叉验证口径不同，如实区分）。
- **八档评测 49/49**：单帧 / RTU 完整性 / 批量日志 / FINS·MELSEC 专项 / 主动探测归因 / 协议自动识别 /
  IEC 104 专项 / EtherNet/IP 专项
  （detect 档含"回显服务器欺骗"与"证据压过端口先验"两类反例）；与裸模型的双跑对比见下节。

## 评测对比 (裸模型基线双跑: 五档 35 用例)

| 档位 | plctap 工具链 | 裸模型直接问答* |
|---|---|---|
| 单帧 Modbus TCP | 8/8 | 8/8 |
| RTU 完整性/CRC | 5/5 | 4/5 |
| 批量日志 (混排) | 5/5 | 3/5 |
| FINS/MELSEC 专项 | 12/12 | 5/12 |
| 主动探测归因 | 5/5 | 4/5 |
| **合计** | **35/35 (100%)** | **24/35 (68.6%)** |

\* 同一批语料双跑, 除工具外一切相同: 裸模型 (glm-5.3-flash, 无工具, temperature=0) 直接问答;
确定性关键词判分 (事实等价集, 双模式共用); 6 例因推理端点超时未获有效答案计 FAIL
(排除超时后 24/29 = 82.8%)。裸模型跑分日期 2026-09-04, 语料版本 317e868 (跑分时点;
fins 语料其后于 b319374 随线上格式修正同步更新, 判分语义不变)。
**范围说明**: 语料建于 M2 (v0.2 时代), 覆盖帧解析 / CRC 完整性 / 日志混排 / 冷门协议语义 /
主动探测归因; v0.3+ 功能 (plc_write / parse_pcap / 透明代理 / modbus_rtu 端点 / vendor_hints /
iec104 端点 / enip 端点 / opcua 端点) 未纳入基线。detect 档 (4 用例, v0.4 新增)、iec104 档 (6 用例, v0.5.2
新增) 与 enip 档 (4 用例, v0.5.3 新增) 需起真实网络服务/台架做主动探测与交互, 不适合裸问答
形式, 故未纳入对比 —— 工具模式八档合计 49/49 (2026-09-07 按当前语料复跑, 见「质量保障」)。
结论: 单帧翻译裸模型已能胜任, **价值差距集中在冷门协议语义与多故障混排场景** ——
这正是确定性解析 + 结构化知识库的所在。方法学与复跑步骤见 [eval/README.md](eval/README.md)。

**运行时边界**: `eval/` 是开发期基准测试 harness (裸模型基线对比), 仅复跑评测时需要
`PLCTAP_` 前缀环境变量 (key/端点/模型全部显式提供, 仓库不内置任何厂商端点);
发布产物只含 `src/plctap` —— MCP server 运行时零 AI/LLM 依赖,
不读也不需要任何模型 API 凭据。

## 多模型裸基线矩阵 (2026-09-08: 4 模型 × 双跑 × 五档 35 用例)

| 模型 (档位) | run1 | run2 | 无答案 run1/run2* |
|---|---|---|---|
| glm-5.3-flash (Agent 同款) | 13/35 | 13/35 | 12 / 11 |
| glm-5-2 (强) | 10/35 | 10/35 | 13 / 14 |
| doubao-seed-turbo (弱) | 9/35 | 9/35 | 14 / 13 |
| deepseek-v4-flash (中) | 8/35 | 8/35 | 2 / 2 |
| **plctap 工具链 (对照, 同语料)** | **35/35** | **35/35** | — |

**换任何裸模型 (弱/中/强/Agent 同款) 都在 8~13/35 徘徊, 冷门协议档 8 轮合计 0/96;
挂上 plctap 工具层后 49/49 (八档), 且与模型强弱无关。** 两种失败模式同时被工具层免疫:
推理跑飞 (八轮 81 次零输出, 单例实测烧满 32768 reasoning tokens 无正文) 与
"流畅的错误" (deepseek-v4-flash 无答案仅 2/2 却总分最低, FINS/MELSEC 档 12 条全错)。

\* 无答案 = 模型零输出 (推理超时), 计 FAIL (09-04 口径沿用)。本矩阵与上表 (2026-09-04,
24/35) **不可同表硬比**: 端点不同 (火山方舟 vs Codex 本地代理)、服务端模型版本可能漂移、
判分等价集为当期校准 —— 同名模型 ≠ 同条件。双跑总分逐分复现 (temperature=0), 分档内部
有小幅漂移。完整矩阵与方法学见 [eval/README.md](eval/README.md)。

## 版本与兼容承诺

自 v0.6.1 起遵循稳定化纪律:
- **向后兼容**: MCP 工具名、参数名与各工具的返回结构保持兼容。返回结构由 pydantic 模型
  定义并锁定 (`tests/test_tool_shapes.py` 黄金校验; 例外: list_protocols 的 protocols
  条目为自由形态 dict); 新增协议端点、新增工具、新增可选参数只增不改。
- **工具 annotations**: 17 个工具的 readOnlyHint/destructiveHint/idempotentHint/openWorldHint
  四项全显式 (server.py `_ANN_*` 四分组), 黄金值锁定于 `tests/test_tool_annotations.py`;
  annotations 属只增元数据, 任何取值变化按 wire 变化对待。
- **破坏性变更**: 若不可避免, 在工具 docstring、本 README 与 Release notes 三处提前标注,
  并尽量提供迁移期。
- **不承诺面**: `src/plctap` 内部模块组织、诊断知识库条目数、评测数字随版本正常演进。
- 1.0 (语义定稿) 的宣布条件: 上述纪律经过至少一个完整发布周期的验证, 届时另行公告。

## License

MIT
