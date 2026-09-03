"""评测 harness 自检: 语料必须全过, 防止 KB/引擎改动悄悄打破评测基线。

eval/ 不是包, 用 importlib 按路径加载 benchmark 模块。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BENCHMARK = _REPO_ROOT / "eval" / "benchmark.py"


def _load_benchmark():
    spec = importlib.util.spec_from_file_location("eval_benchmark", _BENCHMARK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # noqa: SLF001  # 模块级只有常量与函数定义
    return mod


def test_corpus_all_pass():
    mod = _load_benchmark()
    corpus = mod.load_corpus(mod.DEFAULT_CORPUS)
    assert len(corpus) >= 18, f"语料条目数异常: {len(corpus)}"
    passed, total, details = mod.run_tool_mode(corpus)
    failures = {k: v for k, v in details.items() if v != "PASS"}
    assert passed == total, f"评测语料 {passed}/{total} 通过, 失败: {failures}"


def test_export_prompts_count_matches(tmp_path):
    mod = _load_benchmark()
    corpus = mod.load_corpus(mod.DEFAULT_CORPUS)
    out = tmp_path / "prompts.jsonl"
    n = mod.export_prompts(corpus, out)
    assert n == len(corpus)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(corpus)
    import json

    for line in lines:
        rec = json.loads(line)
        assert {"id", "tier", "protocol", "prompt", "grading"} <= set(rec)
        assert rec["prompt"].strip()
