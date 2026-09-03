# plctap

> Agent 的 PLC 驱动层 — 让 Claude / Codex / Cursor 直接连接、读写、诊断
> Modbus TCP / FINS / MELSEC PLC 的 MCP Server。

**状态: 开发中 (M1: Modbus TCP 读写闭环)。** 本 README 将随里程碑补全:
首屏场景演示 GIF、五档评测对比表、三端接入截图。

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
      "args": ["plctap"]
    }
  }
}
```

### Codex 接入 (`~/.codex/config.toml`)

```toml
[mcp_servers.plctap]
command = "uvx"
args = ["plctap"]
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

## 开发

```bash
uv sync
uv run pytest -q   # codec 纯函数单测 (毫秒级) + MCP 冒烟测试
uv run plctap      # 本地启动 stdio server
```

## License

MIT
