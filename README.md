# plctap

<!-- mcp-name: io.github.ymxc152/plctap -->

中文 | [English](README.en.md)

> Agent 的 PLC 驱动层 — 让 Claude / Codex / Cursor 直接连接、读写、诊断
> Modbus TCP / Modbus RTU over TCP / FINS / MELSEC / Siemens S7comm / IEC 60870-5-104 设备的 MCP Server。

![CI](https://github.com/ymxc152/plctap/actions/workflows/ci.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/plctap)](https://pypi.org/project/plctap/)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.ymxc152%2Fplctap-blue)](https://registry.modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

![demo](docs/demo.gif)

**状态: v0.5.2 (协议自动识别 + 透明代理 + 故障注入监听 + 六协议端点接入, 五端点可写 (IEC 104 仅读), IEC 104 经 lib60870 官方实现双向交叉验证)。**

## 工具

| 层 | 工具 | 说明 |
|---|---|---|
| 连接 | `detect_device` | **协议自动识别**: 给 IP 并发探测标准端口, 按响应指纹判定协议/端口/置信度, deep 模式验证读并生成可执行的 plc_read 建议; 全程只读 |
| 连接 | `probe_device` | 连通性探测 + 四类失败分层归因 (MELSEC 支持 3E binary/ASCII 自动回退; IEC 104 为 STARTDT+TESTFR 握手探测) |
| 连接 | `plc_read` | 读数据区并按 datatype/字节序解释 (六个协议端点: modbus / modbus_rtu / fins / melsec / s7 / iec104); datatype 缺省返回 uint16/int16/float32 四种字序 (abcd/cdab/badc/dcba)/int32 多解释 |
| 诊断 | `parse_frame` / `validate_frame` | 单帧结构化解析 / 规范校验清单 |
| 诊断 | `diagnose` | 规则引擎 + 故障知识库 → 结构化候选报告 |
| 诊断 | `parse_pcap` | 解析 Wireshark 导出 pcap, 逐流逐帧 (每条 TCP 流独立判别协议, 需 `uv sync --extra eval`) |
| 监听 | `start_listener` / `stop_listener` / `get_listener_frames` | 钓鱼模式: 设备只能当 client 时立假 server 收帧分析 (三档: record_only / respond_normal / inject_errors 故障注入轮转; MELSEC 回帧支持全部 4 种帧格式; IEC 104 回 STARTDT/TESTFR CON 与总召罐头帧) |
| 监听 | `start_proxy` / `stop_proxy` / `get_proxy_frames` | 透明代理: 上位机 → 代理 → 真实 PLC, 透传同时分帧录制双向帧, 在线联调免 Wireshark (modbus/fins/melsec) |
| 执行 | `plc_write` / `send_frame` | **默认不注册**, `PLCTAP_ALLOW_WRITE=true` 才启用 (闸门) |

## 写能力

`PLCTAP_ALLOW_WRITE=true` 后六端点中五个可写 (modbus_rtu 与 modbus 同轨同语义; iec104 仅读):

| 协议 | 写语义 | options |
|---|---|---|
| Modbus | fc16 批量写寄存器 (默认) / fc05 线圈 / fc06 单寄存器 | `point_type`, `options.function_code`, `options.values` |
| S7 | 16 位字写入 DB/M/I/Q 区 | `options.area`, `options.db_number` |
| FINS | 0102 存储区写字 (CIO/W/H/A/DM/EM) | `options.area` |
| MELSEC | 1401 批量写字, 全部 4 种帧格式 | `options.device`, `options.frame_format` |

所有写/发送动作逐帧写入审计日志 (发送前留痕, 失败也留)。

## 协议速查

六个端点的寻址模型与常用参数 (接入前先对表; 工具内 `list_protocols` 亦可动态获取):

| 端点 | 默认端口 | 地址语义 | 常用 options |
|---|---|---|---|
| `modbus` | 502 | 寄存器地址 **0 基**, count=寄存器数 | `options.function_code`: 3=保持寄存器 (默认), 4=输入寄存器 |
| `modbus_rtu` | 网关自定义 (常见 502 / 8899) | 同 `modbus` (TCP 上跑裸 RTU 帧, 无 MBAP 头) | 同 `modbus` |
| `fins` | 9600 | 字地址, count=字数 | `options.area`: CIO/W/H/A/DM/EM (默认 DM) |
| `melsec` | 44818 (SLMP; 5007 亦常见) | 起始编号, count=点数 (位软元件按 16 点/字) | `options.device`: D/R/W=字, X/Y/B/M=位 (默认 D); `options.frame_format` 4 种 (默认 3e_binary) |
| `s7` | 102 | **字节**地址, count=**字节数** | `options.area`: DB/M/I/Q (默认 DB); `options.db_number` (默认 1); `rack`/`slot` (默认 0/1, S7-300 槽位通常 2) |
| `iec104` | 2404 (2405 亦常见) | IOA 信息对象地址, **总召收集式读**, count=连续 IOA 点数 (M_ME_NC 短浮点每点占 2 个 16 位字) | `options.ca`: 公共地址 (默认 1); `options.qoi`: 总召 QOI (默认 20 站总召) |

`datatype` 支持 uint16 / int16 / float32 / int32; `byteorder` 仅影响 float32 的寄存器对顺序
(big=ABCD, little=DCBA)。datatype 缺省时返回全部常见类型 × 字序的多解释, 字序存疑时直接比对。

示例调用 (客户端中按参数填写):

```text
plc_read(protocol="modbus",     host="10.0.0.10",    port=502,   address=0,   count=2,  datatype="float32", byteorder="big")
plc_read(protocol="modbus_rtu", host="192.168.1.50", port=8899,  unit=2,      address=100, count=10)
plc_read(protocol="fins",       host="10.0.0.30",    port=9600,  address=100, count=10, options={"area": "DM"})
plc_read(protocol="melsec",     host="10.0.0.40",    port=44818, address=100, count=10, options={"device": "D"})
plc_read(protocol="s7",         host="10.0.0.20",    port=102,   address=0,   count=4,  datatype="float32", options={"area": "DB", "db_number": 1})
plc_read(protocol="iec104",     host="10.0.0.60",    port=2404,  address=1,   count=5,  options={"ca": 1})
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

- **482 项单测**（codec 纯函数 + 适配器（含 Modbus RTU / IEC 104）+ 诊断引擎 + 监听器 + 透明代理 + detect_device），CI 每次推送回归。
- **跨厂商 e2e**（[tests/e2e](tests/e2e/test_cross_vendor.py)）：plctap 与 pymodbus、python-snap7、
  pymcprotocol、pypi fins、MZ Automation 官方 lib60870.NET 五个第三方权威实现做真实 socket 交叉验证
  （读写闭环、读数逐值比对、钓鱼监听互通），CI 随行（`uv sync --group e2e`）；
  IEC 104 交叉验证需 .NET 8 SDK（缺省自动跳过）。
- **七档评测 45/45**：单帧 / RTU 完整性 / 批量日志 / FINS·MELSEC 专项 / 主动探测归因 / 协议自动识别 /
  IEC 104 专项
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
(排除超时后 24/29 = 82.8%)。裸模型跑分日期 2026-09-04, 语料版本 7cd6d14 (跑分时点;
fins 语料其后于 7608f47 随线上格式修正同步更新, 判分语义不变)。
**范围说明**: 语料建于 M2 (v0.2 时代), 覆盖帧解析 / CRC 完整性 / 日志混排 / 冷门协议语义 /
主动探测归因; v0.3+ 功能 (plc_write / parse_pcap / 透明代理 / modbus_rtu 端点 / vendor_hints /
iec104 端点) 未纳入基线。detect 档 (4 用例, v0.4 新增) 与 iec104 档 (6 用例, v0.5.2 新增)
需起真实网络服务/台架做主动探测与交互, 不适合裸问答形式, 故未纳入对比 ——
工具模式七档合计 45/45 (2026-09-07 按当前语料复跑, 见「质量保障」)。
结论: 单帧翻译裸模型已能胜任, **价值差距集中在冷门协议语义与多故障混排场景** ——
这正是确定性解析 + 结构化知识库的所在。方法学与复跑步骤见 [eval/README.md](eval/README.md)。

## License

MIT
