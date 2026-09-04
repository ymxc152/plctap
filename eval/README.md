# plctap 评测方法学 (eval/)

## 设计原则 (ARCHITECTURE.md D6 / PLAN.md 第 2 节)

1. **同模型双跑**: 同一批语料, ① 裸模型直接问答 (无工具) ② 挂 plctap MCP 工具。
   除工具外一切相同 (同模型、同 prompt 语言、同温度) —— 单一变量归因于工具层。
2. **确定性判分**: 关键词命中 + 结构断言, 无 LLM judge —— 基线不放水,
   两模式共用同一判分语义 (`benchmark.score_entry` / `baseline.score_answer`)。
3. **分层难度**: 单帧 TCP → RTU 完整性/CRC → 批量日志。
   预期梯度: 越接近真实故障场景, 裸模型与工具的差距越大
   (单帧合法 Modbus TCP 是裸模型最强项, 也是价值最稀薄的场景 —— PLAN.md §0)。

## 语料纪律

- 全部帧为本仓库 codec 构造的合成帧, 不含真实设备报文 (红线 1)
- 每条 expect 字段带注释依据; `tests/test_eval.py` 自检语料基线防回退
- 修 bug 导致期望变化时, 必须同步修改 expect 并在 commit message 说明

## 双跑步骤

```bash
# 工具模式 (本仓库, 无外部依赖)
uv run python eval/benchmark.py

# 裸模式
uv run python eval/benchmark.py --export-prompts eval/prompts.jsonl
export OPENAI_API_KEY=...                       # 必需
export PLCTAP_BASELINE_MODEL=gpt-4.1-mini      # 基线模型, 唯一需要披露的变量
uv run python eval/baseline.py                 # 在线调用 (stdlib, 1s 限速)
# 或离线: 手动收集答案后
uv run python eval/baseline.py --answers answers.jsonl
```

输出: 分档准确率 + `eval/results_baseline.json` (README 对比表数据源)。

## 已发布结果 (2026-09-04)

- 基线: glm-5.3-flash @ 本地 Responses 兼容端点, temperature 0
- 工具 35/35 vs 裸模型 24/35; 分档: 8/8, 4/5, 4/5, 5/12, 5/5
- 6 例端点超时计 FAIL (披露于 README); 判分关键词为事实等价集 (| 语法),
  benchmark/baseline 两处实现已同步

## README 对比表纪律 (M3)

- 必须注明: 基线模型名、日期、语料版本 (git hash)、判分方式
- 工具自评 18/18 单独出现无意义, 必须与裸模型同表对照
- 不做第三方竞品准确率对比 (决策 D6); 功能覆盖对比表不受此限制
