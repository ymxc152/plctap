# Case 04: 44818 端口撞号 —— 端口号是路由线索, 不是协议证据

> 时间锚点: v0.4 detect_device (HANDOFF §5.14) → v0.5.3 EtherNet/IP 接入后显式化 (HANDOFF §5.18)
> 相关代码: `src/plctap/protocols/detect.py` (PORT_PRIORS / _PROFILES), `src/plctap/protocols/melsec/meta.py`, `src/plctap/protocols/enip/meta.py`
> 地址: 本文全部使用 RFC 5737 合成地址 (192.0.2.x / 198.51.100.x)

## 背景/现象

`detect_device` 的设计是三段式: 并发扫描候选端口 (缺省 102/502/2000/2404/44818/5007/6000/9600/9601) → 对每个开放端口并发跑各协议 probe 指纹 (发握手帧、看响应) → 高置信候选按协议做一次最小读验证 (deep)。"识别 ≠ 可访问" (例如 S7 PUT/GET 被关闭时识别照样成功, 但读可能被拒) 是另一条原则, 本文只谈识别。

缺省扫描端口与先验归属 (PORT_PRIORS, 仅同级排序用):

| 端口 | 102 | 502 | 2000/5007/6000 | 2404 | **44818** | 9600/9601 |
|---|---|---|---|---|---|---|
| 先验 | s7 | modbus | melsec | iec104 | **enip (melsec 不构成先验)** | fins |

撞号事实: **44818 既是 EtherNet/IP 的规范端口, 也是 MELSEC SLMP 的常见端口** —— 本仓库两个端点都把 default_port 声明为 44818 (melsec 的 port_hints 是 [44818, 5007], enip 是 [44818, 2222])。场景: 一台只开 44818 的 SLMP 设备, 若按"端口 → 协议"的直觉映射, 会被直接识别成 EtherNet/IP。

## 探测与证据

两个协议的 probe 指纹响应结构完全不重叠, 这就是消歧的物理基础:

- **enip 指纹**: ENIP 封装头自洽, ListIdentity 应答含 CIP Identity 项 (会话建立、封装头字段闭合)。
- **melsec 指纹**: MC 副头部回显正确 (响应副头部 D0 00), 端结码字段自洽 (请求-响应头部回显交叉核对)。

探测流程: 对 44818 并发跑两协议指纹 → 只有一个能拿到结构合法的响应 → 该响应指纹决定候选; deep 开启时再做一次最小读 (enip 读罐头 tag, melsec 读 D 软元件 2 字), 成功则升到 verified。置信度四级, **全部由行为证据决定**:

| 置信度 | 证据来源 |
|---|---|
| verified | deep 最小读成功 (读到数, 逐值可解释) |
| high | probe 指纹成立 (结构合法响应); deep 失败时留痕保持 high |
| medium / low | 更弱的信号档位, 仍只来自响应行为, 永无"端口加分" |

设备回规范异常响应也算在线证据 (如 Modbus 异常帧) —— reachable 语义与识别置信度同一哲学: 只认设备自己说的话。

## 定位

关键设计不变量: **端口先验只影响同级候选的排序 (先验匹配端口优先), 不参与置信度评分**。也就是说端口可以让"两个都像"的候选谁排前面, 但不能让一个候选"更像"。

撞号端口的先验归属经历过一版演进, 不变量始终未动:

- v0.4 时期: 44818 撞号, 先验显式置 None (不押注任何一方);
- v0.5.3 enip 接入后: 44818 先验归属 enip (它是 EtherNet/IP 的**规范**端口), 而 melsec 侧的 44818 只是数字巧合, 不构成先验 —— 5007/6000/2000 才是 melsec 的先验端口。

配套的反例测试 (detect 档语料 `detect_evidence_beats_prior`): 故意把 Modbus 从站摆在 9600 (FINS 的先验端口), 断言识别结果必须是 modbus —— **证据 (探通 + 读到数) 必须压过端口先验**, 防止"先验"滑坡成"投票"。

## 结论与修复

- `PORT_PRIORS` 表内注释固化撞号处理; HANDOFF 增补条款: "新协议注册 _PROFILES 时注意撞号处理" —— 这是注册表模式 (新协议接入 = adapter register + 加一条, 逻辑零改动) 里少数需要人判断的点。
- README 协议速查表显式标注: "enip 44818 (2222 亦常见; **与 MELSEC SLMP 同端口, detect 按响应指纹区分**)" —— 把撞号事实写进用户文档, 而不是藏在代码注释里。
- melsec 探测另有 ASCII 回退收窄纪律 (仅 binary 落入 connected_but_no_reply 时重试), 避免撞号场景下两协议探测互相制造噪声。

## 复盘

- 端口号的熵很低: 它由网络管理员分配、被多协议生态共享、可被任意改写。**先验的正确用法是排序, 不是投票**; 置信度只能由可复现的行为证据 (响应指纹 + 最小读) 决定。
- 撞号不是边角料: 44818 (SLMP/EtherNet/IP)、502 (Modbus TCP/RTU 透传共存) 都是真实共位, "一个端口一个协议"的心智模型在工业现场不成立。
- 评测语料里专门放反例 (evidence beats prior), 是防实现退化的关键 —— 先验逻辑写错的最可能形态就是"端口优先级悄悄变成置信度加分"。
- 同一哲学的另一面: 连接 refused/超时是传输层事实, 不构成任何协议层结论 —— 分层归因 (probe_device 四分类) 与指纹识别共同保证"每一步结论只用该层允许的证据"。

## 如何用 plctap 复现/验证

对一台只开 44818 的设备 (此处用合成地址示例), 完整识别流程:

```text
detect_device(host="192.0.2.50")                        # 缺省扫 9 个标准端口, 含 44818
detect_device(host="192.0.2.50", ports=[44818])         # 只扫撞号端口, 观察 melsec/enip 谁出指纹
detect_device(host="192.0.2.50", ports=[44818], deep=False)   # 跳过验证读, 对比置信度差异
```

手工对照两协议指纹 (哪个 probe 返回结构合法的响应, 哪个就是真身; 另一个应落在 connected_but_no_reply):

```text
probe_device(protocol="enip",   host="192.0.2.50", port=44818)
probe_device(protocol="melsec", host="192.0.2.50", port=44818)
```

确认身份后, detect 返回的 next_step 可直接执行 (deep 验证读与它同参):

```text
plc_read(protocol="melsec", host="192.0.2.50", port=44818, address=0, count=10, options={"device": "D"})
plc_read(protocol="enip",   host="198.51.100.60", port=44818, address="alpha[0]", count=1)
```
