# plctap

[中文](README.md) | **English**

> The PLC driver layer for agents — an MCP server that lets Claude / Codex / Cursor
> connect to, read/write, and diagnose Modbus TCP / Modbus RTU over TCP / FINS / MELSEC / Siemens S7comm / IEC 60870-5-104 devices.

![CI](https://github.com/ymxc152/plctap/actions/workflows/ci.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/plctap)](https://pypi.org/project/plctap/)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.ymxc152%2Fplctap-blue)](https://registry.modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

![demo](docs/demo.gif)

**Status: v0.5.2 (automatic protocol detection + transparent proxy + fault-injection listener + six protocol endpoints, five writable — IEC 104 is read-only; IEC 104 cross-validated bidirectionally against the official lib60870 implementation).**

## Tools

| Layer | Tool | Description |
|---|---|---|
| Connect | `detect_device` | **Automatic protocol detection**: concurrently probes standard ports for a given IP, identifies protocol/port/confidence from response fingerprints; deep mode performs a verification read and produces an executable `plc_read` suggestion; strictly read-only |
| Connect | `probe_device` | Connectivity probe + four-class layered failure attribution (MELSEC supports 3E binary/ASCII automatic fallback; IEC 104 performs a STARTDT+TESTFR handshake probe) |
| Connect | `plc_read` | Reads data areas and interprets by datatype/byte order (six protocol endpoints: modbus / modbus_rtu / fins / melsec / s7 / iec104); with `datatype` omitted, returns multi-interpretations: uint16/int16/float32 in four byte orders (abcd/cdab/badc/dcba)/int32 |
| Diagnose | `parse_frame` / `validate_frame` | Structured single-frame parsing / conformance checklist |
| Diagnose | `diagnose` | Rule engine + fault knowledge base → structured candidate report |
| Diagnose | `parse_pcap` | Parses Wireshark-exported pcap, stream by stream and frame by frame (protocol identified independently per TCP stream; requires `uv sync --extra eval`) |
| Listen | `start_listener` / `stop_listener` / `get_listener_frames` | Honeypot mode: when the device can only act as a client, stand up a fake server to capture frames for analysis (three modes: record_only / respond_normal / inject_errors rotating fault injection; MELSEC responses support all 4 frame formats; IEC 104 answers STARTDT/TESTFR CON and canned interrogation frames) |
| Listen | `start_proxy` / `stop_proxy` / `get_proxy_frames` | Transparent proxy: host app → proxy → real PLC; forwards while framing and recording both directions — online debugging without Wireshark (modbus/fins/melsec) |
| Execute | `plc_write` / `send_frame` | **Not registered by default**; enabled only with `PLCTAP_ALLOW_WRITE=true` (safety gate) |

## Write capability

With `PLCTAP_ALLOW_WRITE=true`, five of the six endpoints are writable (modbus_rtu shares the modbus semantics; iec104 is read-only):

| Protocol | Write semantics | options |
|---|---|---|
| Modbus | fc16 write multiple registers (default) / fc05 coil / fc06 single register | `point_type`, `options.function_code`, `options.values` |
| S7 | 16-bit word writes to DB/M/I/Q areas | `options.area`, `options.db_number` |
| FINS | 0102 area word writes (CIO/W/H/A/DM/EM) | `options.area` |
| MELSEC | 1401 batch word writes, all 4 frame formats | `options.device`, `options.frame_format` |

Every write/send action is logged frame-by-frame to the audit log (recorded before sending; failures are recorded too).

## Protocol quick reference

Addressing model and common options for the six endpoints (also available at runtime via `list_protocols`):

| Endpoint | Default port | Addressing | Common options |
|---|---|---|---|
| `modbus` | 502 | Register address **0-based**, count=registers | `options.function_code`: 3=holding registers (default), 4=input registers |
| `modbus_rtu` | gateway-defined (commonly 502 / 8899) | same as `modbus` (raw RTU frames over TCP, no MBAP header) | same as `modbus` |
| `fins` | 9600 | Word address, count=words | `options.area`: CIO/W/H/A/DM/EM (default DM) |
| `melsec` | 44818 (SLMP; 5007 also common) | Start index, count=points (bit devices in 16-point words) | `options.device`: D/R/W=word, X/Y/B/M=bit (default D); `options.frame_format`, 4 formats (default 3e_binary) |
| `s7` | 102 | **Byte** address, count=**bytes** | `options.area`: DB/M/I/Q (default DB); `options.db_number` (default 1); `rack`/`slot` (default 0/1, S7-300 slot usually 2) |
| `iec104` | 2404 (2405 also common) | IOA information-object address, **interrogation-collected reads**, count=consecutive IOA points (M_ME_NC short float takes 2 words per point) | `options.ca`: common address (default 1); `options.qoi`: interrogation QOI (default 20, station interrogation) |

`datatype` supports uint16 / int16 / float32 / int32; `byteorder` only affects the float32 register-pair order
(big=ABCD, little=DCBA). With `datatype` omitted, the response carries interpretations for all common types ×
byte orders, so an uncertain byte order can be compared directly.

Example calls (fill in the parameters in your client):

```text
plc_read(protocol="modbus",     host="10.0.0.10",    port=502,   address=0,   count=2,  datatype="float32", byteorder="big")
plc_read(protocol="modbus_rtu", host="192.168.1.50", port=8899,  unit=2,      address=100, count=10)
plc_read(protocol="fins",       host="10.0.0.30",    port=9600,  address=100, count=10, options={"area": "DM"})
plc_read(protocol="melsec",     host="10.0.0.40",    port=44818, address=100, count=10, options={"device": "D"})
plc_read(protocol="s7",         host="10.0.0.20",    port=102,   address=0,   count=4,  datatype="float32", options={"area": "DB", "db_number": 1})
plc_read(protocol="iec104",     host="10.0.0.60",    port=2404,  address=1,   count=5,  options={"ca": 1})
```

`modbus` vs `modbus_rtu`: if the gateway/host app already wraps an MBAP header (standard Modbus TCP) → `modbus`;
if a serial server/gateway works in RTU pass-through mode (raw RTU frames over TCP) → `modbus_rtu`.

## Typical workflow (field diagnosis)

1. `detect_device(host=...)` — when you don't know what's on the other end: concurrently probes standard ports,
   identifies protocol/port/confidence from response fingerprints, and returns an executable `plc_read`
   suggestion (strictly read-only).
2. `probe_device(protocol, host, port)` — connectivity check; on failure returns four-class layered attribution
   (connection_refused / timeout / connected_but_no_reply / exception_response), telling you whether to check the
   network route or the protocol configuration (for IEC 104 it performs a STARTDT+TESTFR handshake probe).
3. `plc_read(...)` — read values per the quick reference above, then compare against the host app display or
   expected values.
4. Wrong readings / communication faults → feed captured frames to `parse_frame` / `validate_frame` for
   structured parsing and conformance checks; feed log text to `diagnose` for a structured candidate report
   with an evidence chain.
5. To see everything between the host app and the PLC → `start_proxy` transparent proxy (point the host app at
   the proxy; frames are forwarded while recorded in both directions, no Wireshark needed); if the device can
   only act as a client (outbound connections) → `start_listener` fake-server honeypot, with `inject_errors`
   fault-injection mode for host-app tolerance regression tests.

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
| `PLCTAP_DEFAULT_TIMEOUT_MS` | `2000` | Network timeout (raise it for slow links such as serial gateways / remote sites) |
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

## Quality assurance

- **482 unit tests** (codec pure functions + adapters incl. Modbus RTU / IEC 104 + diagnostics engine + listener + transparent proxy + detect_device), regressed by CI on every push.
- **Cross-vendor e2e** ([tests/e2e](tests/e2e/test_cross_vendor.py)): plctap cross-validated over real sockets against five authoritative third-party
  implementations — pymodbus, python-snap7, pymcprotocol, pypi fins, and the official MZ Automation lib60870.NET
  (read/write closed loops, value-by-value read comparison, honeypot listener interop); runs in CI (`uv sync --group e2e`);
  the IEC 104 cross-validation needs the .NET 8 SDK (skipped automatically when absent).
- **Seven-tier evaluation 45/45**: single frame / RTU integrity / batch logs / FINS·MELSEC specialty / active-probe attribution / automatic protocol detection / IEC 104 specialty
  (the detect tier includes two adversarial cases: "echo-server spoofing" and "evidence outweighing port priors"); dual-run comparison against the bare model follows.

## Evaluation vs. bare-LLM baseline (dual run: five tiers, 35 cases)

| Tier | plctap toolchain | Bare model, direct Q&A* |
|---|---|---|
| Single-frame Modbus TCP | 8/8 | 8/8 |
| RTU integrity/CRC | 5/5 | 4/5 |
| Batch logs (mixed) | 5/5 | 3/5 |
| FINS/MELSEC specialty | 12/12 | 5/12 |
| Active-probe attribution | 5/5 | 4/5 |
| **Total** | **35/35 (100%)** | **24/35 (68.6%)** |

\* The same corpus answered by both modes, identical except for the tools: bare model (glm-5.3-flash, no tools,
temperature=0) answers directly; deterministic keyword scoring (fact-equivalence sets, shared by both modes);
6 cases got no valid answer due to inference-endpoint timeouts and count as FAIL (excluding timeouts:
24/29 = 82.8%). Bare-model run date 2026-09-04, corpus version 7cd6d14 (as of the run; the FINS corpus was
afterwards updated in 7608f47 along with the wire-format fixes, scoring semantics unchanged).
**Scope note**: the corpus was built at milestone M2 (v0.2 era), covering frame parsing / CRC integrity /
mixed logs / niche protocol semantics / active-probe attribution; v0.3+ features (plc_write / parse_pcap /
transparent proxy / modbus_rtu endpoint / vendor_hints / iec104 endpoint) are not in the baseline. The detect
tier (4 cases, added in v0.4) and the iec104 tier (6 cases, added in v0.5.2) require live network services or
benches and do not fit bare Q&A, so they are not in the comparison — tool mode totals 45/45 across seven tiers
(re-run 2026-09-07 on the current corpus; see "Quality assurance").
Conclusion: bare models already handle single-frame translation; the value gap concentrates in **niche protocol
semantics and multi-fault mixed scenarios** — exactly where deterministic parsing + a structured knowledge base
live. Methodology and re-run steps: [eval/README.md](eval/README.md).

## License

MIT
