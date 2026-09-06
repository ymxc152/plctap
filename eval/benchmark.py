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
- active_probe: probe 输入归因, 关键词命中语义同上。
- detect: DeviceDetector 主动探测档 (eval/corpus/detect.yaml)。runner
  按 input.fakes 起 eval/fakes.py 的进程内假设备, 用真实适配器调
  DeviceDetector().detect(host, ports=[fake 端口], deep=True), 判分:
  expect.protocol 须出现在 candidates 且为全条最高置信 (可并列) 且
  不低于 confidence_min; unknown 条目判零候选 + 指名端口落在
  unknown_services。detect 模块未落地 (并行工作流) 时记 SKIP ——
  SKIP 不计入分母也不算 FAIL; 评测环境布置不了 fake (端口被占) 同样 SKIP。

用法: uv run python eval/benchmark.py [--corpus eval/corpus/modbus_m2.yaml]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

_EVAL_DIR = _REPO_ROOT / "eval"
if str(_EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(_EVAL_DIR))  # detect 档 runner 惰性 import eval/fakes

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


# detect 档: 置信序 (detect.py 冻结契约: "verified"|"high"|"medium"|"low")
_CONF_RANK = {"low": 0, "medium": 1, "high": 2, "verified": 3}


def _ensure_adapters_registered() -> None:
    """协议适配器经 import 副作用登记进注册表 (与 tests 同约定)。这里
    显式导入四个协议的 adapter 模块, 保证 DeviceDetector 拿到完整注册表,
    不依赖 detect.py 的内部 import 细节。"""
    from plctap.protocols.fins import adapter as _fins  # noqa: F401
    from plctap.protocols.melsec import adapter as _mc  # noqa: F401
    from plctap.protocols.modbus import adapter as _mb  # noqa: F401
    from plctap.protocols.s7 import adapter as _s7  # noqa: F401


def run_detect_entry(entry: dict[str, Any]) -> tuple[str, list[str]]:
    """detect 档 runner: 按 input.fakes 起进程内假设备 (eval/fakes.py),
    用真实适配器构造 DeviceDetector 做主动探测, 判分见 _score_detect_result。

    返回 ("PASS"|"FAIL"|"SKIP", 说明)。detect 模块由并行工作流实现,
    惰性 import 失败 -> SKIP; 评测环境布置不了 fake (端口被占/被抢) ->
    SKIP (基础设施原因, 不冤枉 detector); 其余异常兜底 FAIL。
    """
    try:
        from plctap.protocols.detect import DeviceDetector  # 惰性 import
    except ImportError:
        return "SKIP", ["detect module not landed yet"]

    import fakes  # eval/fakes.py (sys.path 已含 eval/)

    try:
        return asyncio.run(
            _detect_entry_async(
                DeviceDetector, fakes, entry.get("input", {}), entry.get("expect", {})
            )
        )
    except fakes.PortUnavailable as exc:
        return "SKIP", [f"fake stage failed (infra): {exc}"]
    except Exception as exc:  # noqa: BLE001  兜底: 单条故障不拖垮整个 harness
        return "FAIL", [f"detect case error: {type(exc).__name__}: {exc}"]


async def _detect_entry_async(
    detector_cls: Any, fakes_mod: Any, inp: dict[str, Any], expect: dict[str, Any]
) -> tuple[str, list[str]]:
    """起 fake -> detect -> 判分; fake 与连接池的清理放 try/finally (必须可靠)。"""
    fakes_list = inp.get("fakes") or []
    if not fakes_list:
        return "FAIL", ["input.fakes missing"]
    servers: list[Any] = []
    ports: list[int] = []
    fake_by_name: dict[str, int] = {}
    pool = None
    try:
        for spec in fakes_list:
            fake, host, port = await fakes_mod.start_fake(spec)
            servers.append(fake)
            ports.append(port)
            if spec.get("name"):
                fake_by_name[spec["name"]] = port
        from plctap.config import PlctapConfig
        from plctap.conn.manager import ConnectionPool

        pool = ConnectionPool(idle_timeout_sec=5.0)
        config = PlctapConfig(default_timeout_ms=1000)
        _ensure_adapters_registered()
        detector = detector_cls(pool, config, adapters=None)
        result = await detector.detect(
            host="127.0.0.1", ports=ports, timeout_ms=None, deep=True
        )
        return _score_detect_result(result, expect, ports, fake_by_name)
    finally:
        if pool is not None:
            await pool.close_all()
        for srv in reversed(servers):
            try:
                await srv.stop()
            except Exception:  # noqa: BLE001  收尾尽力而为
                pass


def _score_detect_result(
    result: Any,
    expect: dict[str, Any],
    ports: list[int],
    fake_by_name: dict[str, int],
) -> tuple[str, list[str]]:
    """detect 档判分。expect.protocol: 候选命中且为全条最高置信 (可并列)
    且不低于 confidence_min; expect.no_candidates: 零候选;
    expect.unknown_service: 指名 fake 的端口落在 unknown_services
    (契约元素含 port 字段; 值集合里出现端口也算, 对 schema 演进容错)。"""
    problems: list[str] = []
    cands = list(getattr(result, "candidates", None) or [])
    unknown = list(getattr(result, "unknown_services", None) or [])

    def _summary() -> list[tuple[Any, Any]]:
        return [
            (getattr(c, "protocol", "?"), getattr(c, "confidence", "?")) for c in cands
        ]

    def _rank(cand: Any) -> int:
        return _CONF_RANK.get(getattr(cand, "confidence", ""), -1)

    if expect.get("protocol"):
        want = expect["protocol"]
        matches = [c for c in cands if getattr(c, "protocol", None) == want]
        if not matches:
            problems.append(f"expect protocol={want} in candidates, got {_summary()}")
        else:
            top = max(_rank(c) for c in cands)
            mine = max(_rank(c) for c in matches)
            if mine < top:
                problems.append(f"{want} not top confidence (rank {mine} < {top})")
            conf_min = expect.get("confidence_min")
            if conf_min and mine < _CONF_RANK.get(conf_min, -1):
                problems.append(f"{want} confidence rank {mine} below {conf_min}")
    if expect.get("no_candidates") and cands:
        problems.append(f"expected empty candidates, got {_summary()}")

    if expect.get("unknown_service"):
        want = expect["unknown_service"]
        if isinstance(want, str) and want in fake_by_name:
            target_ports = [fake_by_name[want]]
        elif want is True:
            target_ports = list(ports)
        else:
            target_ports = []
            problems.append(f"unknown_service={want!r} does not match any fake name")
        if target_ports:
            seen = {
                p
                for rec in unknown
                if isinstance(rec, dict)
                for p in target_ports
                if rec.get("port") == p or p in rec.values()
            }
            missing = [p for p in target_ports if p not in seen]
            if missing:
                problems.append(f"unknown_services missing port(s) {missing}: {unknown}")

    return ("FAIL", problems) if problems else ("PASS", [])


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
    """逐条打分, 返回 (通过数, 总数, {id: 结果说明})。

    detect 档条目走 run_detect_entry (独立 runner, 不产 DiagnosticReport);
    SKIP 条目不计入分母也不算 FAIL —— 既有语料 35 条 + detect 档在
    detect 模块落地前后都能全绿。"""
    passed = 0
    total = 0
    details: dict[str, str] = {}
    for entry in corpus:
        eid = entry["id"]
        if entry.get("tier") == "detect":
            status, problems = run_detect_entry(entry)
            if status == "SKIP":
                details[eid] = "SKIP: " + "; ".join(problems)
                continue
            ok = status == "PASS"
        else:
            report = run_entry(entry)
            ok, problems = score_entry(entry, report)
        passed += ok
        total += 1
        details[eid] = "PASS" if ok else "FAIL: " + "; ".join(problems)
    return passed, total, details


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
    n_skipped = sum(1 for v in details.values() if v.startswith("SKIP"))
    tiers: dict[str, list[str]] = {}
    for entry in corpus:
        tiers.setdefault(entry["tier"], []).append(entry["id"])
    for tier, ids in tiers.items():
        t_skip = sum(1 for i in ids if details[i].startswith("SKIP"))
        t_pass = sum(1 for i in ids if details[i] == "PASS")
        line = f"[{tier}] {t_pass}/{len(ids) - t_skip}"
        if t_skip:
            line += f" ({t_skip} skipped)"
        print(line)
        for i in ids:
            if details[i].startswith("SKIP"):
                print(f"  SKIP {i}: {details[i][len('SKIP: '):]}")
            elif details[i] != "PASS":
                print(f"  FAIL {i}: {details[i]}")
    line = f"TOTAL: {passed}/{total}"
    if n_skipped:
        line += f" ({n_skipped} skipped)"
    print(line)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
