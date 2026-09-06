# plctap

<!-- mcp-name: io.github.ymxc152/plctap -->

> Agent 的 PLC 驱动层 — 让 Claude / Codex / Cursor 直接连接、读写、诊断
> Modbus TCP / FINS / MELSEC / Siemens S7comm PLC 的 MCP Server。

![demo](docs/demo.gif)

**状态: v0.3.0 (四协议读写 + 诊断引擎 + 钓鱼监听 + 跨厂商 e2e)。**

## 工具

| 层 | 工具 | 说明 |
|---|---|---|
| 连接 | `probe_device` | 连通性探测 + 四类失败分层归因 (MELSEC 支持 3E binary/ASCII 自动回退) |
| 连接 | `plc_read` | 读数据区并按 datatype/字节序解释 (四协议); datatype 缺省返回 uint16/int16/float32 四种字序 (abcd/cdab/badc/dcba)/int32 多解释 |
| 诊断 | `parse_frame` / `validate_frame` | 单帧结构化解析 / 规范校验清单 |
| 诊断 | `diagnose` | 规则引擎 + 故障知识库 → 结构化候选报告 |
| 诊断 | `parse_pcap` | 解析 Wireshark 导出 pcap, 逐流逐帧 (每条 TCP 流独立判别协议, 需 `uv sync --extra eval`) |
| 监听 | `start_listener` / `stop_listener` / `get_listener_frames` | 钓鱼模式: 设备只能当 client 时立假 server 收帧分析 (MELSEC 回帧支持全部 4 种帧格式) |
| 执行 | `plc_write` / `send_frame` | **默认不注册**, `PLCTAP_ALLOW_WRITE=true` 才启用 (闸门) |

## 写能力

`PLCTAP_ALLOW_WRITE=true` 后四协议能力:

| 协议 | 写语义 | options |
|---|---|---|
| Modbus | fc16 批量写寄存器 (默认) / fc05 线圈 / fc06 单寄存器 | `point_type`, `options.function_code`, `options.values` |
| S7 | 16 位字写入 DB/M/I/Q 区 | `options.area`, `options.db_number` |
| FINS | 0102 存储区写字 (CIO/W/H/A/DM/EM) | `options.area` |
| MELSEC | 1401 批量写字, 全部 4 种帧格式 | `options.device`, `options.frame_format` |

所有写/发送动作逐帧写入审计日志 (发送前留痕, 失败也留)。

## 质量保障

- **412 项单测**（codec 纯函数 + 适配器 + 诊断引擎 + 监听器），CI 每次推送回归。
- **跨厂商 e2e**（[tests/e2e](tests/e2e/test_cross_vendor.py)）：plctap 与 pymodbus、python-snap7、
  pymcprotocol、pypi fins 四个第三方权威实现做真实 socket 交叉验证
  （读写闭环、读数逐值比对、钓鱼监听互通），CI 随行（`uv sync --group e2e`）。
- **五档评测 35/35**：单帧 / RTU 完整性 / 批量日志 / FINS·MELSEC 专项 / 主动探测归因。

## 评测对比 (五档, 35 用例)

| 档位 | plctap 工具链 | 裸模型直接问答* |
|---|---|---|
| 单帧 Modbus TCP | 8/8 | 8/8 |
| RTU 完整性/CRC | 5/5 | 4/5 |
| 批量日志 (混排) | 5/5 | 4/5 |
| FINS/MELSEC 专项 | 12/12 | 5/12 |
| 主动探测归因 | 5/5 | 5/5 |
| **合计** | **35/35 (100%)** | **24/35 (68.6%)** |

\* 基线方法: 同一批语料, 裸模型 (glm-5.3-flash, 无工具, temperature=0) 直接问答;
确定性关键词判分 (事实等价集, 双模式共用); 6 例因推理端点超时未获有效答案计 FAIL
(排除超时后 24/29 = 82.8%)。跑分日期 2026-09-04, 语料版本见 git。
结论: 单帧翻译裸模型已能胜任, **价值差距集中在冷门协议语义与多故障混排场景** ——
这正是确定性解析 + 结构化知识库的所在。

## 快速开始

```bash
uvx plctap          # 或 pipx install plctap
```

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
| `PLCTAP_DEFAULT_TIMEOUT_MS` | `2000` | 网络超时 |

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

## License

MIT

