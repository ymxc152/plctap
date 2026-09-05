# MELSEC MC 协议帧格式完整参考

> 来源: pymcprotocol v0.3.0 (senrust, 103★) + pymelsec v0.2.5 (NothinRandom, 31★) 源码逆向,
> 结合三菱 SLMP Reference Manual (对応 CPU: Q/L/iQ-R/iQ-L/QnA)。

## 帧类型一览 (TCP/Ethernet)

| 帧格式 | 副头部 (binary) | 副头部 (ASCII) | 请求头长度 B/A | 响应头长度 B/A | 适用 CPU | TCP 可用 |
|---|---|---|---|---|---|---|
| 3E binary | 0x5000 | — | 9 | 9 | Q/L/iQ-R/iQ-L | ✅ |
| 3E ASCII | — | "5000" | 18 | 18 | Q/L/iQ-R/iQ-L | ✅ |
| 4E binary | 0x5400 | — | 13 | 13 | Q/L/iQ-R/iQ-L | ✅ |
| 4E ASCII | — | "5400" | 26 | 26 | Q/L/iQ-R/iQ-L | ✅ |
| 4C binary | 0x5400* | — | — | — | QnA 兼容串口 | ⚠️ 仅网关桥接 |
| 4C ASCII | — | "5400"* | — | — | QnA 兼容串口 | ⚠️ 仅网关桥接 |
| 1E binary | 0x00 | — | 4 | 4 | A/QnA 兼容 | ⚠️ 部分以太网单元 |
| 1C binary | 0x00 | — | — | — | A/QnA 串口 | ❌ 仅串口 |

*4C 的副头部结构与 4E 类似但多了校验和字段。

> **本仓库现已支持 3E binary / 3E ASCII / 4E binary / 4E ASCII 全部 4 种 TCP 帧格式** (线上格式经 pymcprotocol + 开源 MC 从站交叉验证)。
> 4C 仅在串口或以太网-串口网关桥接时出现; 1E 仅在 A 系列兼容模式下使用。**优先补齐 3 种 TCP 格式。**

---

## 3E binary (已实现) — 副头部 0x5000

### 请求帧结构
```
偏移  大小  字段                编码
0     2    subheader          0x5000 (big-endian)
2     1    network_no         0x00 (little-endian, 范围 0-255)
3     1    pc_no              0xFF (little-endian, 范围 0-255)
4     2    dest_module_io     0x03FF (little-endian)
6     1    dest_module_sta    0x00 (little-endian)
7     2    request_data_len   = request_data 长度 + timer 长度(2) (little-endian)
9     2    timer              250ms 单位 (little-endian)
11    ...  request_data       command(2B) + subcommand(2B) + device_data + ...
```

### 响应帧结构
```
偏移  大小  字段                编码
0     2    subheader          0xD000 (big-endian, 注意与请求 0x5000 不同)
2     1    network_no         回显
3     1    pc_no              回显
4     2    dest_module_io     回显
6     1    dest_module_sta    回显
7     2    response_data_len  = end_code(2B) + data (little-endian)
9     2    end_code           0x0000=正常, 非 0=异常 (little-endian)
11    ...  response_data      正常时: data; 异常时不存在
```

> 响应帧无监视定时器字段; 响应子头部 0xD000 (D0 00), 可用于请求/响应方向判别。

### batchread (command=0x0401, subcommand=0x0000) 请求 PDU
```
偏移(相对PDU)  大小  字段
0              2    command        0x0401 (little-endian)
2              2    subcommand     0x0000 (word) / 0x0001 (bit) / 0x0002 (iQR word) / 0x0003 (iQR bit)
4              3    device_no      设备号 (3B little-endian, 如 D1000 = 0xE80300)
7              1    device_code    设备代码 (如 D=0xA8)
8              2    device_points  读取点数 (little-endian)
```

### batchread 响应 PDU (正常)
```
偏移(相对PDU)  大小  字段
0              2    data_points × 2  每字 2 字节 little-endian (有符号)
```

---

## 3E ASCII — 副头部 "5000" (ASCII hex)

与 3E binary 结构完全相同, 区别仅是**所有数值用 ASCII 十六进制编码, 宽度翻倍**:

### 请求帧结构
```
偏移  大小  字段                编码 (ASCII hex)
0     4    subheader          "5000" (ASCII)
4     2    network_no         "00" (ASCII hex)
6     2    pc_no              "FF" (ASCII hex)
8     4    dest_module_io     "03FF" (ASCII hex)
12    2    dest_module_sta    "00" (ASCII hex)
14    4    request_data_len   = timer 字符数(4) + request_data 字符数 (ASCII hex)
                              注意: ASCII 帧长度按"字符数"计 (与 pymcprotocol/手册示例一致),
                              与 binary 模式的"字节数"语义不同
18    4    timer              "0004" (ASCII hex)
22    ...  request_data       command(4ASCII) + subcommand(4ASCII) + device_data + ...
```

### 响应帧结构
```
偏移  大小  字段                编码
0     4    subheader          "D000" (ASCII, 注意与请求 "5000" 不同)
4     2    network_no         回显
6     2    pc_no              回显
8     4    dest_module_io     回显
12    2    dest_module_sta    回显
14    4    response_data_len  (ASCII hex, 按字节计)
18    4    end_code           "0000"=正常 (ASCII hex)
22    ...  response_data      每字 4 个 ASCII hex 字符
```

### ASCII 编码规则 (来自 pymcprotocol type3e.py)
```python
# 编码: 整数 → ASCII hex
# byte (1字节):  format(value & 0xFF, "02X")       → 2 字符
# short (2字节): format(value & 0xFFFF, "04X")     → 4 字符
# long (4字节):  format(value & 0xFFFFFFFF, "08X") → 8 字符

# 设备号:
# Q/L 系列: device_code (2 ASCII, 在前) + device_no (6 ASCII, 十进制文本) = 8 字符
#   注意 1: 与二进制模式相反: binary 是 device_no (3B) 在前 + device_code (1B) 在后
#   注意 2: ASCII 的设备号文本按设备自身进制书写 (pymcprotocol 行为):
#           D/M/R = 十进制 (D100 -> "000100"), X/Y/B/W = 十六进制 (X16 -> "000010")
# iQR 系列: device_code (4 ASCII) + device_no (8 ASCII) = 12 字符

# 数据:
# word:  每 16 位 → 4 ASCII hex 字符
# bit:   每 1 位 → 1 ASCII hex 字符 ("0" 或 "1")
```

---

## 4E binary — 副头部 0x5400 (带 serial number)

4E 与 3E 的区别: **多了一个 serial number + 一个保留字段**, 共多 4 字节。
用途: 多客户端并发时区分事务 (类似 Modbus TCP 的 transaction ID)。

### 请求帧结构
```
偏移  大小  字段                编码
0     2    subheader          0x5400 (big-endian)
2     2    subheader_serial   serial number (little-endian, 0-65535, 客户端自定义)
4     2    reserved           0x0000 (little-endian)
6     1    network_no         同 3E
7     1    pc_no              同 3E
8     2    dest_module_io     同 3E
10    1    dest_module_sta    同 3E
11    2    request_data_len   同 3E
13    2    timer              同 3E
15    ...  request_data       同 3E PDU
```

### 响应帧结构
```
偏移  大小  字段                编码
0     2    subheader          0xD400 (big-endian, 注意与请求 0x5400 不同)
2     2    subheader_serial   回显 serial number
4     2    reserved           回显 0x0000
6     1    network_no         回显
7     1    pc_no              回显
8     2    dest_module_io     回显
10    1    dest_module_sta    回显
11    2    response_data_len
13    2    end_code           0x0000=正常
15    ...  response_data      同 3E PDU
```

### 与 3E 的偏移差异
```
              3E binary    4E binary
end_code 偏移  9            13
data 偏移      11           15
头部总长       11           15
```

---

## 4E ASCII — 副头部 "5400"

与 4E binary 结构相同, 所有值用 ASCII hex 编码:

```
偏移  大小  字段                编码
0     4    subheader          "5400"
4     4    subheader_serial   "0000" (ASCII hex)
8     4    reserved           "0000"
12    2    network_no         "00"
14    2    pc_no              "FF"
16    4    dest_module_io     "03FF"
20    2    dest_module_sta    "00"
22    4    request_data_len   (ASCII hex)
26    4    timer              "0004"
30    ...  request_data       同 3E ASCII PDU
```

响应帧:
```
偏移  大小  字段
0     4    subheader          "5400"
4     4    subheader_serial   回显
8     4    reserved           回显
12    2    network_no         回显
14    2    pc_no              回显
16    4    dest_module_io     回显
20    2    dest_module_sta    回显
22    4    response_data_len  (ASCII hex)
26    4    end_code           "0000"=正常
30    ...  response_data      每 16 位 → 4 ASCII 字符
```

---

## 4C (QnA 兼容串口) — 仅串口/网关桥接

4C 帧结构与 4E 完全不同, 使用 ENQ 起始符 + 校验和:

```
[ENQ 1B] [station_no 2B] [pc_no 2B] [command 2B] [subcommand 2B] [data...] [checksum 2B]
```

- 无副头部 (用 ENQ 0x05 作为帧起始标识)
- 所有值用 ASCII 十进制 (不是 hex)
- 校验和 = 从 station_no 到 data 最后一个字节的求和低 8 位
- **TCP 上不直接使用**, 只在 RS-232C/RS-485 或以太网-串口网关桥接时出现

**建议**: v1 不实现 4C, KB 条目提示 "对端可能是 4C 串口帧, 需要网关桥接"。

---

## 1E (A 系列兼容) — 副头部 0x00

1E 帧是最简格式, 用于 A 系列或 Q 系列的 A 兼容模式:

### 请求帧结构 (binary)
```
偏移  大小  字段
0     1    subheader          0x00
1     2    command            (little-endian, 如 0x0001=batchread)
3     2    subcommand         (little-endian)
5     ...  device_data
```

注意: **没有 network/pc/dest_moduleio 等字段**, 没有 timer, 没有 data_length。
设备代码使用 A 系列的编码 (与 Q 系列不同)。

### 响应帧结构
```
偏移  大小  字段
0     1    subheader          0x00
1     2    end_code           (little-endian)
3     ...  response_data
```

**1E 的设备代码与 3E/4E 不同!** 例:
| 设备 | 3E/4E 代码 | 1E 代码 |
|---|---|---|
| D | 0xA8 | 0x44 ("D" 的 ASCII) |
| M | 0x90 | 0x4D ("M" 的 ASCII) |
| X | 0x9C | 0x58 ("X" 的 ASCII) |
| Y | 0x9D | 0x59 ("Y" 的 ASCII) |

**建议**: 1E 仅在需要连接 A 系列 PLC 的以太网单元时实现, 优先级最低。

---

## 汇总: 偏移速查表

| 字段 | 3E B | 3E A | 4E B | 4E A |
|---|---|---|---|---|
| subheader | 0-1 (2B BE) | 0-3 (4 ASCII) | 0-1 (2B BE) | 0-3 (4 ASCII) |
| serial | — | — | 2-3 (2B LE) | 4-7 (4 ASCII) |
| reserved | — | — | 4-5 (2B LE) | 8-11 (4 ASCII) |
| network | 2 (1B) | 4-5 (2 ASCII) | 6 (1B) | 12-13 (2 ASCII) |
| pc | 3 (1B) | 6-7 (2 ASCII) | 7 (1B) | 14-15 (2 ASCII) |
| dest_io | 4-5 (2B LE) | 8-11 (4 ASCII) | 8-9 (2B LE) | 16-19 (4 ASCII) |
| dest_sta | 6 (1B) | 12-13 (2 ASCII) | 10 (1B) | 20-21 (2 ASCII) |
| data_len | 7-8 (2B LE) | 14-17 (4 ASCII) | 11-12 (2B LE) | 22-25 (4 ASCII) |
| timer | 9-10 (2B LE) | 18-21 (4 ASCII) | 13-14 (2B LE) | 26-29 (4 ASCII) |
| **end_code** | **9-10** | **18-21** | **13-14** | **26-29** |
| **data_start** | **11** | **22** | **15** | **30** |
| **头部总长** | **11** | **22** | **15** | **30** |

> 注意: 请求帧中 timer 位于 end_code 位置; 响应帧中该位置是 end_code。
> 所以请求帧的 `data_len` 偏移 = 响应帧的 `data_len` 偏移 = 头部总长 - 4。

---

## 实现建议

### 优先级
1. **4E binary** — TCP 上最常见 (iQ-R/Q 系列多客户端场景), 与 3E binary 仅差 4 字节头部
2. **3E ASCII** — ASCII 模式调试/抓包时常见, 与 3E binary 逻辑一致但编码不同
3. **4E ASCII** — 4E 的 ASCII 版本, 与 4E binary 逻辑一致
4. ~~4C~~ — 串口专用, v1 不做
5. ~~1E~~ — A 系列兼容, 除非用户有 A 系列 PLC, 否则不做

### 实现策略

**不要写 6 个独立 codec 文件。** 共享 PDU 层:

```
src/plctap/protocols/melsec/
  codec.py           # PDU 层: command/subcommand/device 编码解码 (已有)
  frame_3e.py        # 3E 帧: binary + ASCII 两种编码模式
  frame_4e.py        # 4E 帧: binary + ASCII 两种编码模式
  adapter.py         # 根据 frame_format 参数路由到对应帧编解码
```

每个帧格式定义:
- `build_request(pdu: bytes, access_opts) -> bytes`
- `parse_response(frame: bytes) -> MelsecFrameParse`
- `validate_frame(frame: bytes, direction) -> list[CheckResult]`

**3E binary 与 3E ASCII 的差异仅在编码层**, 可以用一个参数控制:

```python
class Frame3E:
    def __init__(self, commtype: str = "binary"):  # "binary" | "ascii"
        self._wordsize = 2 if commtype == "binary" else 4
        self._header_size = 11 if commtype == "binary" else 22
        # ...

    def _encode_value(self, value, mode) -> bytes: ...
    def _decode_value(self, data, mode) -> int: ...
```

**4E 继承 3E**, 只改副头部和加 serial 字段:

```python
class Frame4E(Frame3E):
    subheader = 0x5400
    subheader_serial = 0  # 0-65535

    def _make_senddata(self, request_data):
        mc_data = self._encode_subheader()
        mc_data += self._encode_value(self.subheader_serial, "short")
        mc_data += self._encode_value(0, "short")  # reserved
        mc_data += self._encode_value(self.network, "byte")
        # ... 其余与 3E 相同
```

这样 **1 个基类 + 1 个子类 + binary/ascii 参数 = 覆盖 4 种 TCP 帧格式**。
