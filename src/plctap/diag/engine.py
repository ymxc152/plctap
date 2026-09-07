"""诊断引擎 (D4): 确定性规则匹配 + kb.yaml, 不做任何自然语言生成。

输入是结构化观测 (probe 结果 / 帧解析结果 / 日志片段), 输出按置信度
排序的候选结论。规则全部来自 kb.yaml (与本模块同目录打包):
- entries: 匹配条件 -> 预审定的静态文案 (symptom/root_cause/action)
- references: 命中含数值数据的帧时附加的字节序提示 (不是候选结论)

匹配语义 (kb.yaml 头注): 单条目所有给出的条件都满足才命中;
frame 级条件 (解析报错/检查项/字段) 按帧求值, 任一帧命中即算;
probe 级条件 (failure_class) 对探测结果求值。

日志模式: 从文本里提取连续 hex 串 (>=16 hex 字符即 >= 8 字节, 覆盖
RTU 最短帧) 逐帧解析。纯数字长串 (时间戳) 可能误入, 解析只会产出
结构化错误并归入 observations, 不影响结论 (事实先行, 噪声留痕)。
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from plctap.models import Candidate, DiagnosticReport, ParseResult, ProbeResult
from plctap.protocols.auto import parse_auto

_KB_DIR = Path(__file__).with_name("kb")

# 连续 hex 串 (偶长): >= 16 个 hex 字符 = 8 字节 (Modbus RTU 最短帧)
_HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{16,}(?![0-9a-fA-F])")

# 双轨合并时 RTU 侧的 "形似 RTU" 门控: 这些检查全过才把尾字节当 CRC 校验
_RTU_GATE = frozenset({
    "exception_payload_shape", "request_payload_shape", "response_payload_shape",
})


@lru_cache(maxsize=1)
def _load_kb() -> dict[str, Any]:
    """扫描 kb/ 目录下所有 yaml 文件, 合并 entries + references。"""
    merged: dict[str, Any] = {"entries": [], "references": []}
    for f in sorted(_KB_DIR.glob("*.yaml")):
        with f.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        merged["entries"].extend(data.get("entries", []))
        merged.setdefault("references", []).extend(data.get("references", []))
    return merged


def kb_entries() -> list[dict[str, Any]]:
    """知识库条目 (评测与测试用)。"""
    return _load_kb().get("entries", [])


def kb_entry_ids() -> set[str]:
    return {e["id"] for e in kb_entries()}


# ---------------------------------------------------------------- 观测收集


class _FrameFacts:
    """单帧的观测事实: 方向 + 解析报错 + 校验失败项 + 字段值。"""

    __slots__ = ("direction", "parse_errors", "failed_checks", "fields")

    def __init__(self, parsed: ParseResult, failed_checks: list[str]) -> None:
        self.direction = parsed.direction
        self.parse_errors = parsed.errors
        self.failed_checks = failed_checks
        self.fields = {f.name: f.value for f in parsed.fields}


def _collect_frame(protocol: str, frame: bytes, pending_request: bytes | None) -> tuple[_FrameFacts, bytes | None]:
    """解析一帧并收集事实。返回 (帧事实, 本帧若为请求则带回以供配对)。

    Modbus TCP/RTU 双轨判别 (三档, 决定校验清单与事实来源):
    - TCP 结构合法: 单轨 TCP。合法 TCP 帧的尾字节不是 RTU CRC, 不跑 RTU 轨。
    - TCP 硬解失败但 RTU 能完整解释 (parse_rtu 合法): 单轨 RTU —— 合法
      RTU 帧不该产出 "MBAP 长度不符" 这类按 TCP 硬解的伪结论。
    - 两者都解释不通: 双轨合并。RTU 侧仅在帧 "形似 RTU" (功能码已知且
      payload 形状自洽, 见 validate_rtu) 时纳入, 否则 12 字节 TCP 帧的
      尾字节会被当 CRC 算出 "RTU 校验和错" 噪声, 压过真正的 TCP 结论。

    配对规则: 响应帧紧跟在同一协议的 TCP 请求帧之后时, 用 codec 的
    request 参数重解析, 交叉校验错误 (tid/sid/节点回显) 才能出现 ——
    这正是串包/网关错路由类故障的观测来源。RTU 帧无事务号, 不参与
    配对 (串口侧按地址/功能码回显核对, 不在本引擎范围)。
    """
    from plctap.protocols import codec_for

    codec = codec_for(protocol)
    parsed = parse_auto(protocol, frame)
    track = "tcp"
    if parsed.valid:
        failed = [c.name for c in codec.validate_frame(frame, parsed.direction) if not c.passed]
        facts = _FrameFacts(parsed, failed)
    else:
        rtu = codec.parse_rtu(frame) if protocol == "modbus" else None
        if rtu is not None and rtu.valid:
            track = "rtu"
            failed = [c.name for c in codec.validate_rtu(frame, rtu.direction) if not c.passed]
            facts = _FrameFacts(rtu, failed)
        else:
            failed = [c.name for c in codec.validate_frame(frame, parsed.direction) if not c.passed]
            rtu_checks = codec.validate_rtu(frame) if rtu is not None else []
            gate = _RTU_GATE | {"function_code_known"}
            if all(c.passed for c in rtu_checks if c.name in gate):
                failed.extend(c.name for c in rtu_checks if not c.passed)
            facts = _FrameFacts(parsed, failed)
    if facts.direction == "req" and track == "tcp":
        return facts, frame
    if pending_request is not None:
        reparsed = codec.parse_response(frame, request=pending_request)
        return _FrameFacts(reparsed, facts.failed_checks), None
    return facts, None


# ---------------------------------------------------------------- 规则匹配


def _match_frame(entry: dict[str, Any], frame: _FrameFacts) -> bool:
    m = entry.get("match", {})
    if "exception_code" in m:
        # Modbus 异常码在 exception_code 字段; FINS/MELSEC 在 end_code 字段,
        # 但 KB 用 exception_code 统一表达"设备回的错误码" —— 两个来源都看
        codes = {v for v in (_frame_code(frame, "exception_code"), _frame_code(frame, "end_code")) if v is not None}
        if not codes & set(m["exception_code"]):
            return False
    if "end_code" in m:
        if _frame_code(frame, "end_code") not in m["end_code"]:
            return False
    if "parse_error_contains" in m:
        joined = " | ".join(frame.parse_errors).casefold()
        if not any(s.casefold() in joined for s in m["parse_error_contains"]):
            return False
    if "check_failed" in m:
        if not any(name in frame.failed_checks for name in m["check_failed"]):
            return False
    if "field" in m:
        for name, values in m["field"].items():
            if frame.fields.get(name) not in values:
                return False
    if "field_absent" in m:
        # 字段缺失匹配: 用于区分同字段不同语义的帧 (如 FINS TCP cmd=0x02
        # 既可能是连接拒绝 (无 FINS 载荷) 也可能是数据交换响应 (带 icf))
        for name in m["field_absent"]:
            if name in frame.fields:
                return False
    if "direction" in m and frame.direction != m["direction"]:
        return False
    return True


def _frame_code(frame: _FrameFacts, name: str) -> int | None:
    v = frame.fields.get(name)
    return v if isinstance(v, int) else None


def _match_probe(entry: dict[str, Any], probe: ProbeResult | None) -> bool:
    if "failure_class" not in entry.get("match", {}):
        return True  # 条目不约束探测结果
    if probe is None or not probe.failure_class:
        return False
    return probe.failure_class in entry["match"]["failure_class"]


def _evidence(entry_id: str, frames: list[tuple[int, _FrameFacts]], probe: ProbeResult | None) -> list[str]:
    ev: list[str] = []
    for idx, f in frames:
        ev.append(f"frame[{idx}] direction={f.direction}")
        ev.extend(f"frame[{idx}] parse_error: {e}" for e in f.parse_errors)
        ev.extend(f"frame[{idx}] check_failed: {c}" for c in f.failed_checks)
    if probe is not None and probe.failure_class:
        ev.append(f"probe failure_class={probe.failure_class}")
        if probe.exception_code is not None:
            ev.append(f"probe exception_code={probe.exception_code:#x}")
    return ev or [f"matched kb entry {entry_id} (no extra evidence)"]


# ---------------------------------------------------------------- 主入口


def diagnose(
    protocol: str,
    frames_hex: list[str] | None = None,
    log_snippet: str | None = None,
    probe_result: ProbeResult | None = None,
) -> DiagnosticReport:
    """从观测推导候选结论。三种输入可任意组合, 全缺则返回空报告
    (知识库未覆盖时如实为空, 不硬凑结论)。"""
    observations: list[str] = []
    frames: list[tuple[int, _FrameFacts]] = []
    saw_values = False
    pending_request: bytes | None = None

    for hexstr in frames_hex or []:
        frame = _coerce_frame(hexstr, observations)
        if frame is None:
            continue
        facts, pending_request = _collect_frame(protocol, frame, pending_request)
        frames.append((len(frames), facts))
        if "word_values" in facts.fields:
            saw_values = True
        observations.append(f"frame[{frames[-1][0]}] {len(frame)}B parsed (direction={facts.direction})")

    if log_snippet:
        tokens = _HEX_TOKEN.findall(log_snippet)
        observations.append(f"log_snippet: extracted {len(tokens)} hex token(s)")
        for tok in tokens:
            frame = _coerce_frame(tok, observations)
            if frame is None:
                continue
            facts, pending_request = _collect_frame(protocol, frame, pending_request)
            frames.append((len(frames), facts))
            if "word_values" in facts.fields:
                saw_values = True

    candidates: list[Candidate] = []
    for entry in kb_entries():
        # 协议域过滤: 显式声明协议的条目只对该协议生效 (common.yaml 等
        # "any" 条目跨协议通用)。v0.6 起opcua 引入协议专属 probe 条目
        # (安全策略/会话拒绝), 不过滤会泄漏到其他协议的诊断结果里
        if entry.get("protocol", "any") not in (None, "any", protocol):
            continue
        if not _match_probe(entry, probe_result):
            continue
        matched = [
            (idx, f) for idx, f in frames if _match_frame(entry, f)
        ]
        if not matched and _needs_frame(entry):
            continue
        c = entry["candidate"]
        candidates.append(
            Candidate(
                symptom=c["symptom"],
                root_cause=c["root_cause"],
                evidence=_evidence(entry["id"], matched, probe_result),
                confidence=float(c["confidence"]),
                suggested_action=c["suggested_action"],
                next_tools=c.get("next_tools", []),
            )
        )

    candidates.sort(key=lambda c: c.confidence, reverse=True)

    next_tools: list[str] = []
    for c in candidates:
        for t in c.next_tools:
            if t not in next_tools:
                next_tools.append(t)

    if saw_values:
        observations.extend(_reference_notes(protocol))

    if not candidates and not observations:
        observations.append("no observation provided; give frame_hex / log_snippet / probe inputs")
    if not candidates and observations:
        observations.append("no kb entry matched; knowledge base does not cover this pattern")

    return DiagnosticReport(candidates=candidates, next_tools=next_tools, observations=observations)


def _needs_frame(entry: dict[str, Any]) -> bool:
    """条目含任一帧级条件就必须有帧命中; 仅 probe 条目的条目无需帧。"""
    m = entry.get("match", {})
    return any(k in m for k in ("exception_code", "end_code", "parse_error_contains", "check_failed", "field", "field_absent", "direction"))


def _coerce_frame(hexstr: str, observations: list[str]) -> bytes | None:
    try:
        return bytes.fromhex(hexstr)
    except ValueError:
        observations.append(f"skipped non-hex token: {hexstr[:16]}...")
        return None


def _reference_notes(protocol: str) -> list[str]:
    notes = [r["note"] for r in _load_kb().get("references", []) if r.get("protocol") == protocol]
    return ["reference: " + " ".join(n.split()) for n in notes]
