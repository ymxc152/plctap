"""MCP 工具输出 token 预算测试 (v0.6 收官质量工程项)。

背景: Agent 的上下文窗口是稀缺资源, 批量帧/大日志类工具的输出必须有
体积上限, 防止一次调用把对话撑爆。本文件钉住各工具 "JSON 序列化后
字节数" 的实测最坏值与预算常数 (预算 = 实测最坏 + 余量), 任何让输出
膨胀越过预算的改动都会在这里红。

测法: 不走 socket, 直接构造最坏输入 —— 工具层用 fastmcp 内存 Client
打 create_app 产物 (同 test_smoke), 服务层直接调 registry/模型函数;
结果按紧凑 JSON (与 model_dump_json 同口径) 序列化后 len() 断言。
probe_device / detect_device 输出为固定形状小对象 (字段数固定, identity
由设备决定且仅 ListIdentity 级别), 不在此设断言。

预算表 (工具 -> 上限 -> 实测最坏 -> 依据):
- parse_frame         <=  64KB   实测 ~58KB: FINS/MELSEC 合法最大帧 (16KB
                                 读满数据) 的 word_values + raw_hex 双份载荷;
                                 modbus/iec104/s7 满帧仅 2~7KB, enip 64KB 帧
                                 解析回退 request 侧也 <1KB。约 10% 余量。
- validate_frame      <=   4KB   实测 610B: 校验清单条目数固定、detail 文本短。
- diagnose            <= 256KB   实测 185KB: 100 帧乱码日志 (设备狂吐垃圾帧
                                 的典型现场); 证据链随 帧数x命中条目 线性放大,
                                 500 帧约 940KB —— 收紧须改 diag/engine.py,
                                 不在本次改动范围, 先钉住 100 帧现场。
- parse_pcap          <=  64KB   截断上限硬保证 (pcap._PCAP_OUTPUT_BUDGET_BYTES,
                                 单帧均价 ~800B ≈ 80 帧); 合法最大单帧解析
                                 ~58KB 必然放得下。截断前实测 600 帧 ~450KB。
- get_listener_frames <= 128KB   实测 61.4KB: 默认 limit=100 x modbus 最大帧
                                 (259B)。已知边界: fins/melsec 单帧上限 16KB,
                                 100 帧理论可达 ~3.3MB, 收紧须改 listener.py,
                                 不在本次改动范围。
- get_proxy_frames    <= 128KB   同上 (实测 61.3KB, 收紧须改 proxy.py)。
- list_protocols      <=   8KB   实测 3.4KB: 每协议 ~400B, 8KB 容得下协议数翻倍。
- plc_read (形状)     <=  16KB   形状实测 2.3KB: modbus 合法满读 125 寄存器 +
                                 interpret_all 多解释 dict, 随 count 线性放大。
- plc_browse          <=  32KB   硬上限 200 子节点 (opcua adapter
                                 _BROWSE_MAX_CHILDREN), 实测 ~17KB; 断言在
                                 test_adapter_opcua.py (需 asyncua 台架)。
"""

from __future__ import annotations

import json
import struct

import pytest

try:
    from scapy.all import Ether, IP, Raw, TCP, wrpcap
except ImportError:  # pragma: no cover - 可选依赖 (同 test_pcap.py)
    Ether = IP = Raw = TCP = wrpcap = None

from fastmcp import Client

from plctap.config import PlctapConfig
from plctap.listener import ListenerRegistry, _Listener
from plctap.pcap import _PCAP_OUTPUT_BUDGET_BYTES
from plctap.proxy import ProxyRegistry, _Proxy
from plctap.protocols.common import interpret_all
from plctap.protocols.iec104 import codec as i104
from plctap.server import create_app

# 预算常数 (字节)。理由见模块 docstring 预算表。
BUDGET_PARSE_FRAME = 64 * 1024
BUDGET_VALIDATE_FRAME = 4 * 1024
BUDGET_DIAGNOSE = 256 * 1024
BUDGET_LISTENER_FRAMES = 128 * 1024
BUDGET_PROXY_FRAMES = 128 * 1024
BUDGET_LIST_PROTOCOLS = 8 * 1024
BUDGET_PLC_READ = 16 * 1024
# sentinel 流 + 各流 label 的字节余量 (帧装填只按 PcapFrame 计量)
PCAP_SENTINEL_SLACK = 1024


def _json_size(obj) -> int:
    """工具输出的真实 token 成本 = JSON 序列化后的字节数 (紧凑分隔符)。"""
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump()
    elif isinstance(obj, list):
        obj = [o.model_dump() if hasattr(o, "model_dump") else o for o in obj]
    return len(json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":")))


@pytest.fixture
def app(tmp_path):
    return create_app(PlctapConfig(audit_log=tmp_path / "audit.jsonl"))


# ---------------------------------------------------------------- 最坏输入构造


def _modbus_max_frame() -> bytes:
    """modbus 合法最大帧: fc03 响应带 125 寄存器 (259B, streams 护栏 260B)。"""
    return b"\x00\x01\x00\x00" + struct.pack(">H", 253) + b"\x01\x03\xfa" + b"\x11\x22" * 125


def _fins_max_frame() -> bytes:
    """FINS/TCP 合法最大帧: 0101 读响应读满 (16400B, streams 护栏 0x4000+16)。"""
    count = (0x4000 + 16 - 16 - 14) // 2
    payload = (
        bytes([0xC0, 0, 2])  # ICF=响应(bit6), RSV, GCT
        + bytes([0, 1, 2, 3, 0, 0])  # 目的/源节点路由
        + b"\x55"  # SID
        + struct.pack(">H", 0x0101)  # 读命令
        + b"\x00\x00"  # 端结码正常
        + b"\x00" * (count * 2)  # 数据区读满
    )
    return b"FINS" + struct.pack(">I", 8 + len(payload)) + struct.pack(">I", 0x02) + b"\x00" * 4 + payload


def _melsec_max_frame() -> bytes:
    """MELSEC 3E binary 合法最大帧: 0401 响应数据区读满 (16415B, 护栏 0x4000+32)。"""
    words = (0x4000 + 32 - 9 - 2) // 2
    return b"\xd0\x00" + b"\x00" * 5 + struct.pack("<H", 2 + words * 2) + b"\x00\x00" + b"\x00" * (words * 2)


def _iec104_max_frame() -> bytes:
    """IEC 104 合法最大 I 帧: 总召罐头监视帧塞满 APDU (252B, 规范上限 255)。"""
    objs = [(i, [0x01]) for i in range(200, 200 + 60)]
    return i104.build_apci_objects(i104.M_SP_NA_1, objs, 20, 1, 1, 1)


def _s7_full_read_response() -> bytes:
    """S7 读响应: 960B 数据区 (PDU 现实上限量级), 复刻真实帧结构扩数据段。"""
    head = bytes.fromhex("0300001D02F0803203000000010002001F00000401FF04")
    data = b"\x41\x97" * 480
    frame = head + struct.pack(">H", len(data)) + data
    return frame[:2] + struct.pack(">H", len(frame)) + frame[4:]  # 修正 TPKT 长度


def _enip_max_frame() -> bytes:
    """ENIP 合法最大帧: SendRRData 大 tag 读回 (65550B, 护栏 0xFFFF+24)。"""
    from plctap.protocols.enip import codec as enip

    cip = bytes([0xCC, 0, 0, 0]) + struct.pack("<H", 0xC4) + b"".join(
        struct.pack("<I", i) for i in range(16000)
    )
    return enip.build_send_rr_data(1, cip)


# ---------------------------------------------------------------- 帧级工具


async def test_parse_frame_budget(app):
    """各协议合法最大帧的解析输出都不得越过 64KB 预算。"""
    async with Client(app) as client:
        cases = {
            "modbus": _modbus_max_frame(),
            "fins": _fins_max_frame(),
            "melsec": _melsec_max_frame(),
            "iec104": _iec104_max_frame(),
            "s7": _s7_full_read_response(),
            "enip": _enip_max_frame(),
        }
        for protocol, frame in cases.items():
            result = await client.call_tool(
                "parse_frame", {"protocol": protocol, "frame_hex": frame.hex()}
            )
            n = _json_size(result.data)
            assert n <= BUDGET_PARSE_FRAME, f"{protocol} parse 输出 {n}B 超预算 {BUDGET_PARSE_FRAME}B"


async def test_validate_frame_budget(app):
    """校验清单输出固定形状, 满帧下也不得越过 4KB 预算。"""
    async with Client(app) as client:
        cases = {
            "modbus": _modbus_max_frame(),
            "fins": _fins_max_frame(),
            "melsec": _melsec_max_frame(),
        }
        for protocol, frame in cases.items():
            result = await client.call_tool(
                "validate_frame",
                {"protocol": protocol, "frame_hex": frame.hex(), "direction": "resp"},
            )
            n = _json_size(result.data)
            assert n <= BUDGET_VALIDATE_FRAME, f"{protocol} validate 输出 {n}B 超预算 {BUDGET_VALIDATE_FRAME}B"


# ---------------------------------------------------------------- diagnose


async def test_diagnose_budget(app):
    """大 log_snippet (100 帧乱码) 的候选+证据链不得越过 256KB 预算。

    这是当前最大的放大器: 证据链行数 = 帧数 x 命中条目数。更大日志会
    继续线性放大 (500 帧实测 ~940KB), 收紧须改 diag/engine.py。
    """
    garbage = "DEADBEEF01234567"  # 8B 乱码帧: 解析必然报错, 命中 parse_error 条目
    log = "\n".join(f"2026-09-07 10:00:{i % 60:02d} rx {garbage}" for i in range(100))
    async with Client(app) as client:
        result = await client.call_tool(
            "diagnose", {"protocol": "modbus", "log_snippet": log}
        )
    n = _json_size(result.data)
    assert n <= BUDGET_DIAGNOSE, f"diagnose 输出 {n}B 超预算 {BUDGET_DIAGNOSE}B"
    assert result.data.candidates  # 乱码现场本就该给出候选结论, 预算没把结论掐死


# ---------------------------------------------------------------- 监听/代理取帧


def _record_listener_frames(reg: ListenerRegistry, port: int, n: int, frame: bytes) -> None:
    """不走 socket 直接构造 listener 环形缓冲内容 (复用真实 _record 路径)。"""
    lst = _Listener(
        protocol="modbus", host="127.0.0.1", requested_port=0, port=port,
        mode="record_only", server=None,
    )
    reg._listeners[port] = lst
    for _ in range(n):
        reg._record(lst, "recv", "127.0.0.1:50000", frame)


def test_get_listener_frames_budget():
    reg = ListenerRegistry()
    _record_listener_frames(reg, 50901, 100, _modbus_max_frame())
    frames = reg.frames(50901)  # 默认 limit=100
    assert len(frames) == 100  # limit 语义本身是预算的一部分
    n = _json_size(frames)
    assert n <= BUDGET_LISTENER_FRAMES, f"get_listener_frames 输出 {n}B 超预算 {BUDGET_LISTENER_FRAMES}B"


def test_get_proxy_frames_budget():
    reg = ProxyRegistry()
    pr = _Proxy(
        protocol="modbus", listen_port=50902,
        target_host="127.0.0.1", target_port=502, server=None,
    )
    reg._proxies[50902] = pr
    for _ in range(100):
        # 逐帧 dict 与 proxy._pump_dir 录制形状一致
        pr.frames.append({
            "ts": "2026-09-07T10:00:00",
            "direction": "c2s",
            "peer": "127.0.0.1:50000",
            "frame_hex": _modbus_max_frame().hex(),
        })
    frames = reg.frames(50902)  # 默认 limit=100
    assert len(frames) == 100
    n = _json_size(frames)
    assert n <= BUDGET_PROXY_FRAMES, f"get_proxy_frames 输出 {n}B 超预算 {BUDGET_PROXY_FRAMES}B"


# ---------------------------------------------------------------- 无 socket 的形状预算


def test_plc_read_shape_budget():
    """plc_read 输出形状预算: modbus 合法满读 (125 寄存器) + 多解释 dict。

    不走 socket, 直接构造 ReadResult —— 预算约束的是序列化形状
    (寄存器列表 + interpretations 随 count 线性放大), 与连接成败无关。
    """
    from plctap.models import ReadResult, Target

    regs = list(range(125))
    rr = ReadResult(
        target=Target(protocol="modbus", host="10.0.0.1", port=502),
        address=0,
        request_frame="00010000000601030000007d",
        raw_registers=regs,
        interpreted=regs,
        elapsed_ms=5,
    )
    rr.interpretations = interpret_all(regs)
    n = _json_size(rr)
    assert n <= BUDGET_PLC_READ, f"plc_read 满读形状 {n}B 超预算 {BUDGET_PLC_READ}B"


# ---------------------------------------------------------------- list_protocols


async def test_list_protocols_budget(app):
    """能力自述表: 8KB 容得下现有协议数翻倍。"""
    async with Client(app) as client:
        result = await client.call_tool("list_protocols", {})
    n = _json_size(result.data)
    assert n <= BUDGET_LIST_PROTOCOLS, f"list_protocols 输出 {n}B 超预算 {BUDGET_LIST_PROTOCOLS}B"


# ---------------------------------------------------------------- parse_pcap 截断


def _write_modbus_pcap(path, pairs: int) -> str:
    """合成 modbus 抓包: pairs 对请求/响应 (2*pairs 帧), 单流顺序 seq。"""
    from plctap.protocols.modbus.codec import build_read_request

    req = build_read_request(1, 1, 3, 0, 2)
    resp = bytes.fromhex("0001000000050103020000")
    pkts = []
    seq = 1000
    for i in range(pairs):
        pkts.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=502, dport=40000, seq=seq, flags="PA") / Raw(load=req))
        seq += len(req)
        pkts.append(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
            sport=40000, dport=502, seq=2000 + i * len(resp), flags="PA") / Raw(load=resp))
    wrpcap(str(path), pkts)
    return str(path)


@pytest.mark.skipif(Ether is None, reason="scapy not installed")
def test_parse_pcap_truncation_budget_and_sentinel(tmp_path):
    """600 帧抓包必须被预算截断: 输出 <= 预算+sentinel 余量, sentinel 带 total。"""
    from plctap import pcap as pcap_mod

    path = _write_modbus_pcap(tmp_path / "big.pcap", 300)  # 600 帧, 不截断时实测 ~450KB
    flows = pcap_mod.parse_pcap_file(path, "modbus")
    n = _json_size(flows)
    assert n <= _PCAP_OUTPUT_BUDGET_BYTES + PCAP_SENTINEL_SLACK, (
        f"parse_pcap 输出 {n}B 超预算 {_PCAP_OUTPUT_BUDGET_BYTES}B(+sentinel)"
    )
    # sentinel 流在末尾: truncated 标记 + total/shown 计数, frames 为空
    sentinel = flows[-1]
    assert sentinel.flow.startswith("truncated:")
    assert "total 600 frames" in sentinel.flow
    assert sentinel.frames == []
    shown = sum(len(f.frames) for f in flows[:-1])
    assert 0 < shown < 600, "预算内应装下部分帧且确实发生了截断"
    assert f"showing first {shown}" in sentinel.flow  # 计数自洽
    # 装帧按流序/帧序: 第一条流从第一帧开始, 内容未被预算破坏
    assert flows[0].frames[0].parsed is not None and flows[0].frames[0].parsed.valid


@pytest.mark.skipif(Ether is None, reason="scapy not installed")
def test_parse_pcap_small_capture_no_sentinel(tmp_path):
    """预算内的小抓包行为不变: 无 sentinel (既有 test_pcap.py 用例的语义保障)。"""
    from plctap import pcap as pcap_mod

    path = _write_modbus_pcap(tmp_path / "small.pcap", 2)  # 4 帧
    flows = pcap_mod.parse_pcap_file(path, "modbus")
    assert len(flows) == 1
    assert len(flows[0].frames) == 4
    assert all(not f.flow.startswith("truncated:") for f in flows)
