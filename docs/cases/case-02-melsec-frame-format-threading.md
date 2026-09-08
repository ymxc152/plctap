# Case 02: MELSEC frame_format 未贯穿收帧回调 —— 默认参数掩盖下的参数断链

> 时间锚点: v0.2.0 全帧格式实装 → 2026-09-06 全量交叉验证修复 (提交 84dad0a, HANDOFF §5.12)
> 相关代码: `src/plctap/protocols/melsec/adapter.py` (_recv_frame / _RESP_SUBHEADER_TO_FORMAT), `src/plctap/protocols/base.py` (locked_exchange)
> 帧样例: 本仓库 codec 合成帧 (红线 1), 台架地址 127.0.0.1

## 背景/现象

MC/3E 是无会话协议: 每帧自描述, 无握手。以太网侧共四种帧格式: 3E/4E × binary/ASCII (副头部 0x5000/"5000" 与 0x5400/"5400", 响应侧 0xD000/D000、0xD400/D400)。架构上, 通用 `locked_exchange()` 封装"目标级锁内一次请求-响应", 收帧逻辑以**回调**传入适配器 —— 收多少字节取决于帧格式 (binary 数据长是 2 字节小端, ASCII 是 4 字符 hex 文本), 所以收帧回调必须知道 frame_format。

v0.2.0 宣称支持全部 4 种格式, 单测全绿。台架实测: **3E binary 一切正常; 3E ASCII / 4E / 4E ASCII 的读必挂**, 报 `bad response subheader 0x4430` —— 0x44='D'、0x30='0', 正是 ASCII 应答 "D000..." 的前两个字节被当成二进制副头部去校验的样子。真机复现一致。

四种格式的实测矩阵 (断链同源, 表象各异):

| 格式 | 响应副头部 (正确) | 被按 3E binary 收帧后的实际行为 | 结果 |
|---|---|---|---|
| 3E binary | D0 00 | 恰好等于默认假设 | 误判为"正常" |
| 3E ASCII | "D000" (0x44 0x30 0x30 0x30) | 副头部校验对不上, 数据长偏移也错位 | 必挂, `0x4430` |
| 4E binary | D4 00 | 副头部 D400 ≠ 期待 D000 | 必挂 |
| 4E ASCII | "D400" | 同 ASCII 断链 + 4E 头长差异 | 必挂 |

各格式头部几何 (收帧切帧依赖的关键差异, 详见 docs/MELSEC_FRAME_FORMATS.md 汇总表):

| 字段 | 3E B | 3E A | 4E B | 4E A |
|---|---|---|---|---|
| 头部总长 | 11 | 22 | 15 | 30 |
| 数据长偏移 | 7-8 (2B LE) | 14-17 (4 字符 hex 文本) | 11-12 (2B LE) | 22-25 (4 字符 hex 文本) |
| end_code 偏移 | 9 | 18 | 13 | 26 |

## 探测与证据

1. **发帧侧先排除**: 抓发出去的请求帧, 3E ASCII 请求的副头部 "5000"、ASCII 编码全部正确 —— `build_read_request(frame_format=...)` 的参数链是通的。
2. **收帧侧对账**: 收帧回调 `_recv_frame` 的签名里 frame_format 有**默认值 "3e_binary"**; `locked_exchange` 传的是 `self._recv_frame` 这个**函数引用**, 调用处并没有把格式带上 —— 于是永远按默认值 3E binary 切帧、校验。
3. **为什么单测全绿**: 3E binary 的"正确格式"恰好等于默认值, 断链被默认参数掩盖成假阴性; 二进制 4E 应答 (副头部 D400) 被按 3E binary 校验、ASCII 应答被按二进制算数据长偏移, 全部落在同一条断链上。
4. **顺带发现第二处同族缺陷**: ASCII 帧的数据长是 4 字符 hex 文本 (请求侧按字符数计、含 4 字符定时器; 响应侧按字节数计, 详见 docs/MELSEC_FRAME_FORMATS.md), 旧实现按 2 字节小端去解 —— 帧格式差异必须收发两侧都分派, 只改一侧等于没改。

## 定位

根因一句话: **asyncio 回调传的是函数引用, 不是"带着参数的调用"** —— 参数存在于构建请求的那层调用栈里, 没有随闭包/绑定走进回调。教训不是"忘了传参", 而是这一类 bug 有两个放大器: ① 默认参数让断链只在非默认路径上爆炸 (而测试恰恰最容易只覆盖默认路径); ② 四种格式共享同一条收帧代码, 一个断点同时打挂三个变体, 表象上像"多格式支持整体不可靠", 其实是一处断链。

## 结论与修复

提交 84dad0a (2026-09-06), 三件事一起做:

1. **显式绑定**: `functools.partial(self._recv_frame, frame_format=frame_format)` 把参数焊死在回调对象上, 不依赖调用方记得传。该纪律已写入 HANDOFF "新会话必读": 新协议加参数时用 partial 显式绑定。
2. **auto 兜底**: `_recv_frame` 支持 `frame_format="auto"`, 按响应副头部判别 (`_RESP_SUBHEADER_TO_FORMAT`: D000/D400 二进制, "D0"/"D4" ASCII); `send_raw` 无法预知对端格式, 走 auto —— 副头部不匹配即报"流失步", 不静默错切。
3. **ASCII 数据长按 4 字符 hex 文本解析**, 收发两侧按格式分派; 回归测试 +9 (多帧格式读写 / probe ASCII 回退 / 写闭环, FakeMcServerAuto 四格式参数化 + send_raw auto), 全量 383 绿。

## 复盘

- 参数贯穿要在"**发帧 → 收帧回调**"整条链上验证, 而不是只验证"发出去的帧对不对" —— 本案例发帧侧完全正确, 挂在收帧侧的隐式默认值上。
- 默认参数是最危险的隐蔽断点: 它让 bug 从"必现"降级为"仅非默认路径必现", 而非默认路径往往正是新功能所在。
- "同协议多变体"特性 (4 帧格式、后续 IEC 104 的帧型) 的测试必须是**每个变体独立参数化**的假服务器回归 (FakeMcServerAuto), 单一格式回归对变体断链零覆盖。
- Python 的 bound method 没有稳定身份, 同族问题 (实例级 `self.write is Base.write` 恒 False) 在同一次交叉验证里被抓出, 一并改为类级比较 —— 回调/方法引用在 Python 里的"身份"与"行为"是两件事。

## 如何用 plctap 复现/验证

单帧解析: 对语料中的 3E binary 应答帧 (端结码 C04F, 参数超出允许范围) 显式指定格式; 再分别试 auto —— 二进制按 D0/D4、ASCII 按 "D0"/"D4" 判别:

```text
parse_frame(protocol="melsec", frame_hex="d00000ffff030002004fc0", frame_format="3e_binary")
parse_frame(protocol="melsec", frame_hex="d00000ffff0300e7030000", frame_format="3e_binary")
```

实机/台架上验证格式贯穿 (任何一格式不通都会以 ProtocolError 显式报副头部不匹配, 而不是错切):

```text
probe_device(protocol="melsec", host="127.0.0.1", port=6000)
plc_read(protocol="melsec", host="127.0.0.1", port=6000, address=0, count=2, options={"device": "D", "frame_format": "3e_ascii"})
plc_read(protocol="melsec", host="127.0.0.1", port=6000, address=0, count=2, options={"device": "D", "frame_format": "4e_binary"})
```

ASCII 回退的边界 (只在 binary 落入 connected_but_no_reply 时重试 ASCII, 传输层故障不重试):

```text
probe_device(protocol="melsec", host="192.0.2.40", port=6000)
```

监听器四格式回帧互通验证:

```text
start_listener(protocol="melsec", mode="respond_normal", port=0)
get_listener_frames(port=<实际端口>)
stop_listener(port=<实际端口>)
```
