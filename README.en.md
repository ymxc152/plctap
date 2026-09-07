# plctap

[中文](README.md) | **English**

> The PLC driver layer for agents — an MCP server that lets Claude / Codex / Cursor
> connect to, read/write, and diagnose Modbus TCP / Modbus RTU over TCP / FINS / MELSEC / Siemens S7comm / IEC 60870-5-104 / EtherNet/IP (CIP) PLCs.

![CI](https://github.com/ymxc152/plctap/actions/workflows/ci.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/plctap)](https://pypi.org/project/plctap/)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.ymxc152%2Fplctap-blue)](https://registry.modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

![demo](docs/demo.gif)

**Status: v0.5.3 (automatic protocol detection + transparent proxy + fault-injection listener + read/write across seven protocol endpoints; IEC 104 cross-validated against official lib60870, EtherNet/IP against pycomm3).**

## Tools

| Layer | Tool | Description |
|---|---|---|
| Connect | `detect_device` | **Automatic protocol detection**: concurrently probes standard ports for a given IP, identifies protocol/port/confidence from response fingerprints; deep mode performs a verification read and produces an executable `plc_read` suggestion; strictly read-only |
| Connect | `probe_device` | Connectivity probe + four-class layered failure attribution (MELSEC supports 3E binary/ASCII automatic fallback) |
| Connect | `plc_read` | Reads data areas and interprets by datatype/byte order (seven protocol endpoints: modbus / modbus_rtu / fins / melsec / s7 / iec104 / enip); with `datatype` omitted, returns multi-interpretations: uint16/int16/float32 in four byte orders (abcd/cdab/badc/dcba)/int32 |
| Diagnose | `parse_frame` / `validate_frame` | Structured single-frame parsing / conformance checklist |
| Diagnose | `diagnose` | Rule engine + fault knowledge base → structured candidate report |
| Diagnose | `parse_pcap` | Parses Wireshark-exported pcap, stream by stream and frame by frame (protocol identified independently per TCP stream; requires `uv sync --extra eval`) |
| Listen | `start_listener` / `stop_listener` / `get_listener_frames` | Honeypot mode: when the device can only act as a client, stand up a fake server to capture frames for analysis (three modes: record_only / respond_normal / inject_errors rotating fault injection; MELSEC responses support all 4 frame formats) |
| Listen | `start_proxy` / `stop_proxy` / `get_proxy_frames` | Transparent proxy: host app → proxy → real PLC; forwards while framing and recording both directions — online debugging without Wireshark (modbus/fins/melsec) |
| Execute | `plc_write` / `send_frame` | **Not registered by default**; enabled only with `PLCTAP_ALLOW_WRITE=true` (safety gate) |

## Write capability

With `PLCTAP_ALLOW_WRITE=true`, all four protocols:

| Protocol | Write semantics | options |
|---|---|---|
| Modbus | fc16 write multiple registers (default) / fc05 coil / fc06 single register | `point_type`, `options.function_code`, `options.values` |
| S7 | 16-bit word writes to DB/M/I/Q areas | `options.area`, `options.db_number` |
| FINS | 0102 area word writes (CIO/W/H/A/DM/EM) | `options.area` |
| MELSEC | 1401 batch word writes, all 4 frame formats | `options.device`, `options.frame_format` |

Every write/send action is logged frame-by-frame to the audit log (recorded before sending; failures are recorded too).

## Quality assurance

- **461 unit tests** (codec pure functions + adapters incl. Modbus RTU + diagnostics engine + listener + transparent proxy + detect_device), regressed by CI on every push.
- **Cross-vendor e2e** ([tests/e2e](tests/e2e/test_cross_vendor.py)): plctap cross-validated over real sockets against four authoritative third-party
  implementations — pymodbus, python-snap7, pymcprotocol, and pypi fins
  (read/write closed loops, value-by-value read comparison, honeypot listener interop); runs in CI (`uv sync --group e2e`).
- **Six-tier evaluation 39/39**: single frame / RTU integrity / batch logs / FINS·MELSEC specialty / active-probe attribution / automatic protocol detection
  (the detect tier includes two adversarial cases: "echo-server spoofing" and "evidence outweighing port priors").

## Evaluation vs. bare-LLM baseline (dual run: five tiers, 35 cases)

| Tier | plctap toolchain | Bare model, direct Q&A* |
|---|---|---|
| Single-frame Modbus TCP | 8/8 | 8/8 |
| RTU integrity/CRC | 5/5 | 4/5 |
| Batch logs (mixed) | 5/5 | 4/5 |
| FINS/MELSEC specialty | 12/12 | 5/12 |
| Active-probe attribution | 5/5 | 5/5 |
| **Total** | **35/35 (100%)** | **24/35 (68.6%)** |

\* Baseline method: the same corpus answered directly by the bare model (glm-5.3-flash, no tools, temperature=0);
deterministic keyword scoring (fact-equivalence sets, shared by both modes); 6 cases got no valid answer due to
inference-endpoint timeouts and count as FAIL (excluding timeouts: 24/29 = 82.8%). Run date 2026-09-04; corpus
version in git.
Conclusion: bare models already handle single-frame translation; the value gap concentrates in **niche protocol
semantics and multi-fault mixed scenarios** — exactly where deterministic parsing + a structured knowledge base live.
The table above is the dual-runnable five-tier baseline; the detect tier (automatic protocol detection, 4 cases,
added in v0.4) requires live network services for active probing and does not fit bare Q&A, so it is not in the
baseline — tool mode totals 39/39 across six tiers (see "Quality assurance").

## Quick start

```bash
uvx plctap          # or: pipx install plctap
```

Listed in the official MCP Registry: [`io.github.ymxc152/plctap`](https://registry.modelcontextprotocol.io/)
(clients that support search/install by name can discover this server directly).

### Claude Desktop (`claude_desktop_config.json`)

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

Local development (checked-out repo path):

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

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.plctap]
command = "uvx"
args = ["plctap"]

[mcp_servers.plctap.env]
PLCTAP_ALLOW_WRITE = "false"        # write gate off by default
PLCTAP_DEFAULT_TIMEOUT_MS = "2000"
```

### Configuration (environment variables, all have defaults)

| Variable | Default | Description |
|---|---|---|
| `PLCTAP_ALLOW_WRITE` | `false` | **Write tools are not registered by default** (safety gate) |
| `PLCTAP_POOL_MAX_PER_TARGET` | `2` | Per-target connection pool cap |
| `PLCTAP_IDLE_TIMEOUT_SEC` | `30` | Idle connection reclaim seconds |
| `PLCTAP_DEFAULT_TIMEOUT_MS` | `2000` | Network timeout |
| `PLCTAP_AUDIT_LOG` | `~/.plctap/audit.jsonl` | Audit log path (frame-by-frame trace of writes/sends) |

## Security

- Write operations are **not registered at all** by default; only explicit `PLCTAP_ALLOW_WRITE=true` enables them.
- Every write/send is recorded line by line to a JSONL audit log (`~/.plctap/audit.jsonl`, cannot be disabled).
- For send-type calls, use them together with your client's approval prompt (the user sees the target IP and the full frame).
- Audit log sample:
  `{"ts":"2026-09-04T01:20:33+0800","tool":"plc_write","target":"modbus://127.0.0.1:15020 unit=1","frame_hex":"0002000000060106000104d2","caller":"mcp"}`

## Development

```bash
uv sync --extra eval --group e2e
uv run pytest -q   # unit tests (codec/adapters/diagnostics/listener) + cross-vendor e2e + MCP smoke
uv run plctap      # start the stdio server locally
```

## License

MIT
