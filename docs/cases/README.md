# 诊断案例集 (docs/cases/)

plctap v0.6 收官内容资产: 五篇脱敏诊断案例, 全部取材于本仓库真实开发史 (v0.2 → v0.5.5),
每篇按 **背景/现象 → 探测与证据 → 定位 → 结论与修复 → 复盘 → 如何用 plctap 复现/验证** 叙事。
既是面试讲故事的素材, 也是"技术细节经得起追问"的自查稿 —— 每篇的时间锚点、提交号、代码路径、
帧样例都与 HANDOFF.md / git log / 源码对得上。

## 脱敏红线 (全部案例适用)

- IP 只用合成地址 (192.0.2.x / 198.51.100.x / 127.0.0.1 / 10.0.0.x 段);
- 不含真实设备型号组合、公司信息、业务寄存器语义;
- 帧样例全部取自仓库评测语料/测试金标的合成帧 (`eval/corpus/`、`tests/test_smoke.py`), 台架端口为 127.0.0.1 高位端口。

## 索引

| 案例 | 一句话钩子 | 适合回答的面试问题类型 |
|---|---|---|
| [case-01-fins-cmd-variants.md](case-01-fins-cmd-variants.md) | FINS/TCP 数据帧命令字 0x04 vs 0x02: 单实现对照得出错误"主流", 三生态实现交叉验证 + 真机定案 —— 协议规范留了变体空间, 生态实测才是判据 | 如何处理文档与实现不一致 / 你怎么验证一个协议字段的真实语义 / 讲一次你推翻自己早期技术判断的经历 |
| [case-02-melsec-frame-format-threading.md](case-02-melsec-frame-format-threading.md) | MELSEC frame_format 未贯穿 locked_exchange 收帧回调: 3E binary 正常、3E ASCII/4E 必挂, asyncio 回调传的是函数引用, functools.partial 显式绑定修复 —— 参数贯穿要在发帧→收帧整条链上验证 | 讲一个隐蔽的异步/回调 bug / 为什么单测全绿还能挂 / 多变体特性怎么设计回归测试 |
| [case-03-rtu-dual-track.md](case-03-rtu-dual-track.md) | 合法 RTU 帧按 Modbus TCP 硬解会产出"形似 MBAP"的伪候选: 诊断引擎双轨三档判别 (TCP 单轨 / RTU 单轨 / 双败合并 + 形似 RTU 门控) 的设计动机 —— 伪候选会挤掉真结论 | 你怎么设计诊断/告警系统降噪 / 讲一次用测试语料倒逼架构设计 / 确定性规则引擎 vs LLM 的取舍 |
| [case-04-port-44818-ambiguity.md](case-04-port-44818-ambiguity.md) | 44818 端口撞号: MELSEC SLMP 与 EtherNet/IP 同端口, 端口号不能当协议证据 —— detect 端口先验只影响同级排序不参与置信度, 靠响应指纹消歧 | 先验知识在系统里的正确用法 / 识别与认证式的"确认"怎么分层 / 你怎么设计反例评测防实现退化 |
| [case-05-s7-write-audit-bypass.md](case-05-s7-write-audit-bypass.md) | S7 write 漏调 on_frame → 写操作完全绕过审计日志 (安全红线级缺陷): 全量 pytest 只测过 modbus 写审计所以漏网, 发布 wheel 台架审计逐帧计数才发现 —— 测试全绿 ≠ 安全闭环, 验收方法学才能兜底 | 讲一次你抓到的最严重的安全缺陷 / 测试覆盖率说明不了什么 / 怎么给安全属性设计验收流程 / 上线前最后一道工序的价值 |

## 推荐使用方式

- 面试叙事: 每篇的"复盘"一节是结论句, "探测与证据"一节是过程细节, 可按面试时长裁剪;
- 技术追问: 每篇结尾"如何用 plctap 复现/验证"给出可直接执行的参数化调用示例 (风格与根目录 README 一致),
  追问到底层时帧结构参考 docs/MELSEC_FRAME_FORMATS.md 与各协议 codec 源码;
- 方法学延伸: 评测双跑设计 (同模型、同语料、确定性判分) 见 eval/README.md,
  新协议接入的契约 (含 case-05 的防复发条款) 见 docs/ADD_PROTOCOL.md。
