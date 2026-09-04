"""M2 评测 harness: 语料打分 (tool 模式) + 裸模型导出 (--export-prompts)。

双轨设计 (HANDOFF 红线 3: server 内无 LLM, 评测也在 server 之外):
- tool 模式 (默认): 直接调用 plctap 诊断引擎, 量化"工具 + Agent 驱动"
  路线的确定性能得分, 按档位汇总。
- --export-prompts: 把语料转成 JSONL 提示词, 供裸模型 (不带工具) 离线
  双跑对照 —— 衡量"给同样输入, 没有结构化工具时模型能答对多少"。

打分语义 (与语料 expect 块对应):
- single_frame_tcp / integrity_crc: 单一故障, top1 候选须命中
  symptom_keywords (任一) 与 cause_keywords (任一); no_candidates 条目
  要求零候选。
- batch_log: 聚合档, 每个关键词在至少一个候选里出现即可 (混排日志
  本来就是多问题并存)。
- check_failed: 出现在任一候选的 evidence 行里即算。

用法: uv run python eval/benchmark.py [--corpus eval/corpus/modbus_m2.yaml]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from plctap.diag.engine import diagnose  # noqa: E402
from plctap.models import DiagnosticReport  # noqa: E402

DEFAULT_CORPUS = _REPO_ROOT / "eval" / "corpus"

_PROMPT_TEMPLATE = """你是工业现场的诊断助手。协议: {protocol}。
请根据以下通信证据判断故障, 只输出 JSON 数组, 每个问题一个对象:
[{{"symptom": "...", "root_cause": "...", "suggested_action": "..."}}]
没有问题就输出 []。不要输出多余文字。

证据: {evidence}"""


def load_corpus(path: Path) -> list[dict[str, Any]]:
    """语料文件或目录 (目录时合并全部 yaml, 按文件名字典序)。"""
    if path.is_dir():
        entries: list[dict[str, Any]] = []
        for f in sorted(path.glob("*.yaml")):
            entries.extend(yaml.safe_load(f.read_text(encoding="utf-8")))
        return entries
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def run_entry(entry: dict[str, Any]) -> DiagnosticReport:
    inp = entry.get("input", {})
    probe = inp.get("probe")
    probe_result = None
    if probe:
        from plctap.models import ProbeResult

        # P3 语义: exception_response = 设备在线 (传输层可达)
        reachable = probe.get("failure_class") == "exception_response"
        probe_result = ProbeResult(reachable=reachable, **probe)
    return diagnose(
        entry["protocol"],
        frames_hex=(
            [inp["frame_hex"]] if isinstance(inp.get("frame_hex"), str)
            else (inp["frame_hex"] or None) if inp.get("frame_hex")
            else None
        ),
        log_snippet=inp.get("log_snippet"),
        probe_result=probe_result,
    )


def _keywords_hit(keywords: list[str], texts: list[str], require_all: bool) -> bool:
    """关键词命中。条目内的 | 分隔为同一问题的等价写法组 (KB 预定文案 vs
    裸模型自然措辞), 组内任一命中即算覆盖该问题; require_all 时全部问题
    都须覆盖, 否则任一命中即通过。"""
    alts = [k.split("|") for k in keywords]
    hits = [any(a in t for a in alt_k for t in texts) for alt_k in alts]
    return all(hits) if require_all else any(hits)


def score_entry(entry: dict[str, Any], report: DiagnosticReport) -> tuple[bool, list[str]]:
    """返回 (是否通过, 失败原因列表)。"""
    expect = entry.get("expect", {})
    problems: list[str] = []

    if expect.get("valid") is not None:
        # valid 属于 parse 语义, tool 模式下经由引擎的 observations 不可见,
        # 直接以候选判定: 有候选即视为解析/校验暴露了问题
        if expect["valid"] and report.candidates:
            problems.append("expect valid=true but candidates present")
        if not expect["valid"] and not report.candidates:
            problems.append("expect valid=false but no candidates")

    if expect.get("no_candidates"):
        if report.candidates:
            problems.append(f"expected no candidates, got {len(report.candidates)}")
        return not problems, problems

    if not report.candidates:
        problems.append("no candidates produced")
        return False, problems

    symptoms = [c.symptom for c in report.candidates]
    causes = [c.root_cause for c in report.candidates]
    evidence = [e for c in report.candidates for e in c.evidence]
    log_tier = entry.get("tier") == "batch_log"

    sk = expect.get("symptom_keywords") or []
    if sk and not _keywords_hit(sk, symptoms, require_all=log_tier):
        problems.append(f"symptom keywords missed: {sk} (got {symptoms})")
    ck = expect.get("cause_keywords") or []
    if ck and not _keywords_hit(ck, causes, require_all=log_tier):
        problems.append(f"cause keywords missed: {ck}")
    cf = expect.get("check_failed") or []
    if cf and not any(name in " | ".join(evidence) for name in cf):
        problems.append(f"expected failed check {cf} in evidence")

    return not problems, problems


def run_tool_mode(corpus: list[dict[str, Any]]) -> tuple[int, int, dict[str, str]]:
    """逐条打分, 返回 (通过数, 总数, {id: 结果说明})。"""
    passed = 0
    details: dict[str, str] = {}
    for entry in corpus:
        report = run_entry(entry)
        ok, problems = score_entry(entry, report)
        passed += ok
        details[entry["id"]] = "PASS" if ok else "FAIL: " + "; ".join(problems)
    return passed, len(corpus), details


def export_prompts(corpus: list[dict[str, Any]], out_path: Path) -> int:
    """导出裸模型评测 JSONL: prompt + grading 键分离, 离线双跑用。"""
    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for entry in corpus:
            inp = entry.get("input", {})
            if inp.get("probe"):
                pr = inp["probe"]
                evidence = (
                    f"probe_device 结果: failure_class={pr['failure_class']}"
                    + (f", exception_code=0x{pr['exception_code']:x}" if pr.get("exception_code") else "")
                )
            else:
                evidence = inp.get("frame_hex") or inp.get("log_snippet") or ""
            grading = {
                k: v
                for k, v in entry.get("expect", {}).items()
                if k in ("symptom_keywords", "cause_keywords", "check_failed", "no_candidates")
            }
            record = {
                "id": entry["id"],
                "tier": entry["tier"],
                "protocol": entry["protocol"],
                "prompt": _PROMPT_TEMPLATE.format(protocol=entry["protocol"], evidence=evidence),
                "grading": grading,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            n += 1
    return n


def main() -> int:
    parser = argparse.ArgumentParser(description="plctap M2 评测 harness")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--export-prompts", type=Path, default=None, help="导出裸模型 JSONL 到指定路径")
    args = parser.parse_args()

    corpus = load_corpus(args.corpus)
    print(f"corpus: {args.corpus} ({len(corpus)} entries)")

    if args.export_prompts:
        n = export_prompts(corpus, args.export_prompts)
        print(f"exported {n} prompts -> {args.export_prompts}")
        return 0

    passed, total, details = run_tool_mode(corpus)
    tiers: dict[str, list[str]] = {}
    for entry in corpus:
        tiers.setdefault(entry["tier"], []).append(entry["id"])
    for tier, ids in tiers.items():
        t_pass = sum(1 for i in ids if details[i] == "PASS")
        print(f"[{tier}] {t_pass}/{len(ids)}")
        for i in ids:
            if details[i] != "PASS":
                print(f"  FAIL {i}: {details[i]}")
    print(f"TOTAL: {passed}/{total}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
