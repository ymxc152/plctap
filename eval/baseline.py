# -*- coding: utf-8 -*-
"""裸模型基线评测 runner (eval/README.md 的方法学实现)。

流程:
  1) uv run python eval/benchmark.py --export-prompts eval/prompts.jsonl
  2) uv run python eval/baseline.py --prompts eval/prompts.jsonl
       - 需要环境变量 OPENAI_API_KEY; 模型用 PLCTAP_BASELINE_MODEL (默认 gpt-4.1-mini)
       - 无 key 时可用 --answers <jsonl> 离线判分 (answer 字段 = 模型原始输出)
  3) 输出分档准确率 + eval/results_baseline.json (README 对比表数据源)

判分与工具模式同源同义: symptom/root_cause 关键词任一命中, no_candidates
对应空数组。判分器是确定性字符串匹配, 无 LLM judge —— 基线不放水。
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any


def _keywords_hit(keywords: list[str], text: str) -> bool:
    """与 benchmark._keywords_hit 同语义: 条目内 | 分隔为等价写法组。"""
    t = text.lower()
    return any(a.lower() in t for k in keywords for a in k.split("|"))


def score_answer(grading: dict[str, Any], answer: list[dict[str, Any]] | None, raw: str) -> tuple[bool, list[str]]:
    """与 benchmark.score_entry 同义的判分 (输入是模型自由文本答案)。"""
    problems: list[str] = []
    if grading.get("no_candidates"):
        if answer:
            problems.append("expected no candidates (empty []), got answers")
        return not problems, problems
    if not answer:
        return False, ["expected candidates, model returned []"]
    top = answer[0]
    symptom = str(top.get("symptom", ""))
    cause = str(top.get("root_cause", ""))
    if grading.get("symptom_keywords") and not _keywords_hit(grading["symptom_keywords"], symptom):
        problems.append(f"symptom keywords miss: {symptom!r}")
    if grading.get("cause_keywords") and not _keywords_hit(grading["cause_keywords"], cause):
        problems.append(f"cause keywords miss: {cause!r}")
    return not problems, problems


def parse_model_output(raw: str) -> list[dict[str, Any]] | None:
    """容忍 ```json 围栏与前后噪声; 解析失败返回 None (计为错误)。"""
    s = raw.strip()
    if s.startswith("```"):
        s = s.strip("`")
        s = s[s.index("\n") + 1 :] if "\n" in s else s
    start, end = s.find("["), s.rfind("]")
    if start == -1 or end == -1:
        return None
    try:
        data = json.loads(s[start : end + 1])
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # 容忍对象包装: {"candidates":[...]} 或单个 {"symptom":...}
        if isinstance(data.get("candidates"), list):
            return data["candidates"]
        if "symptom" in data or "root_cause" in data:
            return [data]
    return None


def call_model(prompt: str, model: str, timeout: int = 180) -> str:
    """Responses API (stdlib 调用, 不引入依赖)。

    支持 OpenAI 官方或任意兼容端点:
      PLCTAP_BASELINE_BASE_URL  默认 https://api.openai.com/v1
      OPENAI_API_KEY            鉴权 key
    部分兼容端点不接受 temperature —— 400 时自动去参重试。
    """
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise SystemExit("OPENAI_API_KEY not set")
    base = os.environ.get("PLCTAP_BASELINE_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    url = f"{base}/responses"

    def _post(body_dict: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            url,
            data=json.dumps(body_dict).encode(),
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    try:
        data = _post({"model": model, "input": prompt, "temperature": 0})
    except urllib.error.HTTPError as e:
        if e.code == 400:  # 兼容端点可能不支持 temperature
            data = _post({"model": model, "input": prompt})
        else:
            raise
    if data.get("output_text"):
        return data["output_text"]
    # 兼容无 output_text 快捷字段的实现: 从 output 数组提取文本
    texts = []
    for item in data.get("output", []):
        for part in item.get("content", []):
            if part.get("type") in ("output_text", "text"):
                texts.append(part.get("text", ""))
    return "".join(texts)


def main() -> int:
    ap = argparse.ArgumentParser(description="plctap 裸模型基线评测")
    ap.add_argument("--prompts", type=Path, default=Path("eval/prompts.jsonl"))
    ap.add_argument("--answers", type=Path, default=None, help="离线模式: 预录答案 JSONL {id, raw}")
    ap.add_argument("--only-missing", action="store_true",
                    help="续跑: 合并已有 results_baseline.json, 只重调 raw 为空的用例")
    ap.add_argument("--out", type=Path, default=Path("eval/results_baseline.json"))
    args = ap.parse_args()

    records = [
        json.loads(line)
        for line in args.prompts.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    answers: dict[str, str] = {}
    prev_results: dict[str, dict] = {}
    if args.only_missing and args.out.exists():
        prev = json.loads(args.out.read_text(encoding="utf-8"))
        prev_results = prev.get("details", {})
        for cid, r in prev_results.items():
            if r.get("raw"):
                answers[cid] = r["raw"]
        print(f"resume: {len(answers)}/{len(records)} already answered")
    if args.answers:
        for line in args.answers.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                answers[rec["id"]] = rec["raw"]
        print(f"offline mode: {len(answers)} pre-recorded answers")
    else:
        model = os.environ.get("PLCTAP_BASELINE_MODEL", "gpt-4.1-mini")
        print(f"baseline model: {model} @ {os.environ.get('PLCTAP_BASELINE_BASE_URL', 'https://api.openai.com/v1')}")
        for rec in records:
            if rec["id"] in answers:
                continue
            t0 = time.time()
            for attempt in (1, 2):  # 网络超时重试一次
                try:
                    answers[rec["id"]] = call_model(rec["prompt"], model)
                    print(f"  {rec['id']}: {time.time()-t0:.1f}s (attempt {attempt})", flush=True)
                    time.sleep(1.0)  # 温和限速
                    break
                except Exception as e:  # noqa: BLE001
                    print(f"  {rec['id']}: ERROR (attempt {attempt}) {e}", flush=True)
                    if attempt == 2:
                        answers[rec["id"]] = ""
                    time.sleep(3.0)

    tiers: dict[str, list[str]] = {}
    results: dict[str, dict[str, Any]] = {}
    passed_total = 0
    for rec in records:
        raw = answers.get(rec["id"], "")
        parsed = parse_model_output(raw) if raw else None
        ok, problems = score_answer(rec["grading"], parsed, raw)
        passed_total += ok
        tiers.setdefault(rec["tier"], []).append(rec["id"])
        results[rec["id"]] = {
            "tier": rec["tier"], "pass": ok,
            "answer": (parsed or [{}])[0] if parsed else None,
            "raw": raw,
            "problems": problems,
        }

    summary = {"total": len(records), "passed": passed_total, "tiers": {}}
    for tier, ids in sorted(tiers.items()):
        t_pass = sum(1 for i in ids if results[i]["pass"])
        summary["tiers"][tier] = {"pass": t_pass, "total": len(ids)}
        print(f"[{tier}] {t_pass}/{len(ids)}")
        for i in ids:
            if not results[i]["pass"]:
                print(f"  FAIL {i}: {'; '.join(results[i]['problems'])}")
    print(f"TOTAL (bare model): {passed_total}/{len(records)}")
    args.out.write_text(json.dumps(summary | {"details": results}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"results -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
