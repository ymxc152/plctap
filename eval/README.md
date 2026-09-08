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

## 已发布结果 (裸模型跑分 2026-09-04, 语料版本 7cd6d14)

- 基线: glm-5.3-flash @ 本地 Responses 兼容端点, temperature 0
- 工具 35/35 vs 裸模型 24/35; 分档: 8/8, 4/5, 3/5, 5/12, 4/5
  (single_frame / integrity_crc / batch_log / fins_melsec / active_probe)
- 6 例端点超时计 FAIL (披露于 README); 判分关键词为事实等价集 (| 语法),
  benchmark/baseline 两处实现已同步
- fins 语料其后于 7608f47 (v0.2.0) 随 MELSEC 线上格式修正同步更新 (帧输入与判分
  关键词, 判分语义不变); 工具模式 2026-09-07 按当前语料复跑
- v0.4 (2026-09-07): 新增 detect 档 4 例 (`corpus/detect.yaml`, 进程内假设备);
  v0.5.2: 新增 iec104 档 6 例 (`corpus/iec104.yaml`, 总召帧与 lib60870 官方实现
  逐字节比对); v0.5.3: 新增 enip 档 4 例 (`corpus/enip.yaml`, 帧结构与 pycomm3
  官方实现交叉验证) —— 三档均需真实网络服务/台架, 无裸问答基线, 工具模式八档
  合计 49/49
- **范围**: 语料建于 M2 (v0.2 时代); v0.3+ 功能 (plc_write / parse_pcap /
  透明代理 / modbus_rtu 端点 / vendor_hints / iec104 端点 / enip 端点) 未纳入基线
- `results_baseline.json` 为生成物 (已 gitignore, 可按上文步骤再生);
  README 对比表数字以本节为准

## 多模型裸基线矩阵 (v0.6, 2026-09-08)

- **矩阵**: 4 模型 × 双跑 × 五档 35 条, 判分/温度/超时口径与 09-04 完全同源 (脚本零改动):
  glm-5.3-flash 13/35、glm-5-2 10/35、doubao-seed-turbo 9/35、deepseek-v4-flash 8/35 ——
  双跑总分逐分复现 (temperature=0), 分档内部有小幅漂移 (同总分不同分布)
- **模型与档位** (服务端版本以当期 Ark 为准): glm-5.3-flash (Agent 同款, coding 网关) /
  glm-5-2-260617 (强) / doubao-seed-2-1-turbo-260628 (弱) / deepseek-v4-flash-ga-260731 (中)
- **无答案口径**: `raw` 为空 (模型零输出/推理超时) 计 FAIL, 沿用 09-04。八轮 81 次;
  单例实证 glm-5-2 600s 烧满 32768 reasoning tokens 零正文 —— 超时计 FAIL 是正确口径而非
  环境缺陷; deepseek 无答案仅 2/2 但总分最低 ("流畅的错误": fins_melsec 档 12 条全错)
- **fins_melsec 档 8 轮合计 0/96** (工具模式 12/12): 冷门协议语义是所有裸模型的绝对盲区
- **特例披露** (1 例): glm52 run1 `rtu_ok` (no_candidates 类条目) 空答案按脚本既有语义
  自动判过 —— 09-04 同语义, 单例如实披露
- **可比性**: 本矩阵与 09-04 的 24/35 **不可同表硬比** —— 端点不同 (火山方舟 Ark vs
  Codex 本地代理)、服务端模型版本可能漂移、判分等价集为当期校准; 同名 ≠ 同条件。
  README 以独立「多模型裸基线」表并列, 核心句: 换任何裸模型都在 8~13/35 徘徊,
  挂工具层后 49/49 且与模型强弱无关
- **方法学教训**: 评测批跑须用独占直连端点 (本地 Codex 代理与并行会话争抢并发,
  180s 超时率 3/4); Ark coding 网关 base 必须是 `/api/coding/v3` (`/api/coding` 全 404)
  且模型 ID 带点 (`glm-5.3-flash`, v3 响应规范化为 `glm-5-3-flash`)
- `results_baseline_v06_{model}_run{1,2}.json` ×8 为生成物 (gitignore 通配覆盖, raw 全留档,
  可按上文步骤 + env 换模型再生); 09-04 历史 `results_baseline.json` 原样未动

## README 对比表纪律 (M3)

- 必须注明: 基线模型名、日期、语料版本 (git hash)、判分方式
- 工具自评 18/18 单独出现无意义, 必须与裸模型同表对照
- 不做第三方竞品准确率对比 (决策 D6); 功能覆盖对比表不受此限制
