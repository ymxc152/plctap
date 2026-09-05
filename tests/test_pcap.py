"""parse_pcap 测试 (M3: scapy 生成合成 pcap, 红线 1 无真实抓包)。

scapy 是可选依赖 (pyproject eval extra), 缺失时整文件跳过。
"""

from __future__ import annotations

import pytest

from plctap import pcap
from plctap.protocols.modbus.codec import build_read_request

try:
    from scapy.all import Ether, IP, Raw, TCP, wrpcap
except ImportError:  # pragma: no cover - 可选依赖
    Ether = IP = Raw = TCP = wrpcap = None

pytestmark = pytest.mark.skipif(Ether is None, reason="scapy not installed")


def _write_pcap(path, packets):
    wrpcap(str(path), packets)
    return str(path)


def test_parse_pcap_modbus_request_and_response(tmp_path):
    req = build_read_request(1, 1, 3, 0, 2)
    resp = bytes.fromhex("0001000000050103020000")  # 合法读响应 (2 寄存器)
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=502, dport=40000, seq=1000, flags="PA") / Raw(load=req),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=40000, dport=502, seq=2000, flags="PA") / Raw(load=resp),
    ]
    flows = pcap.parse_pcap_file(_write_pcap(tmp_path / "x.pcap", pkts))
    assert len(flows) == 1
    frames = flows[0].frames
    assert len(frames) == 2
    assert frames[0].parsed.direction == "req" and frames[0].parsed.valid
    assert frames[1].parsed.direction == "resp" and frames[1].parsed.valid
    assert not frames[0].partial and not frames[1].partial


def test_parse_pcap_autodetect_protocol(tmp_path):
    # 不传 protocol: 应选出能切出完整帧最多的协议 (modbus)
    req = build_read_request(1, 1, 3, 0, 2)
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=502, dport=40000, seq=1, flags="PA") / Raw(load=req)
    flows = pcap.parse_pcap_file(_write_pcap(tmp_path / "x.pcap", [pkt]))
    assert flows[0].frames[0].parsed.protocol == "modbus"


def test_parse_pcap_partial_tail_reported(tmp_path):
    # 尾部半帧 (抓包截断) 以 partial 浮出, 不静默丢弃
    req = build_read_request(1, 1, 3, 0, 2)
    payload = req + req[:4]
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=502, dport=40000, seq=1, flags="PA") / Raw(load=payload)
    flows = pcap.parse_pcap_file(_write_pcap(tmp_path / "x.pcap", [pkt]), "modbus")
    frames = flows[0].frames
    assert len(frames) == 2
    assert frames[0].partial is False
    assert frames[1].partial is True
    assert frames[1].frame_hex == req[:4].hex()


def test_parse_pcap_seq_gap_keeps_framing(tmp_path):
    # seq 跳变 (丢包/乱序) 后按新 seq 续接, 不整段丢弃
    req = build_read_request(1, 1, 3, 0, 2)
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=502, dport=40000, seq=1000, flags="PA") / Raw(load=req),
        # seq 从 2000 开始 (中间有缺口), 载荷仍是完整一帧
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=502, dport=40000, seq=2000, flags="PA") / Raw(load=req),
    ]
    flows = pcap.parse_pcap_file(_write_pcap(tmp_path / "x.pcap", pkts), "modbus")
    assert len(flows[0].frames) == 2


def test_parse_pcap_missing_scapy_message(tmp_path, monkeypatch):
    # 未装 scapy 时给出明确安装提示 (用 monkeypatch 模拟 ImportError)
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name == "scapy.all":
            raise ImportError("no scapy")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="scapy"):
        pcap.parse_pcap_file("whatever.pcap")


def test_parse_pcap_mixed_protocols_per_flow(tmp_path):
    """回归: 混合协议 pcap 逐流判别 —— FINS 流不再被全局多数协议 (modbus) 淹没。"""
    fins_req = bytes.fromhex(
        "46494e530000001a0000000200000000800002000b00000b00000101820064000003"
    )
    fins_cfm = bytes.fromhex(
        "46494e53000000100000000100000000000000020000000b"
    )
    mc_req = bytes.fromhex("500000ffff03000c00040001040000640000a80500")
    mc_resp = bytes.fromhex("d00000ffff03000c00000000000000000000000000")
    modbus_req = build_read_request(1, 1, 3, 0, 2)
    pkts = []
    # 流1: FINS (3 帧, 少于 modbus 的 4 帧 —— 旧全局判别会被 modbus 淹没)
    for i, f in enumerate([fins_req, fins_cfm, fins_req]):
        seq = 100 + sum(len(x) for x in [fins_req, fins_cfm, fins_req][:i])
        pkts.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=9600, seq=seq, flags="PA") / Raw(load=f))
    # 流2: MELSEC
    for i, f in enumerate([mc_req, mc_resp]):
        seq = 200 + sum(len(x) for x in [mc_req, mc_resp][:i])
        pkts.append(Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=50001, dport=6000, seq=seq, flags="PA") / Raw(load=f))
    # 流3: modbus (请求+响应×2 = 4 帧, 全局帧数最多)
    for i in range(2):
        pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=50002, dport=502, seq=300 + i * len(modbus_req), flags="PA") / Raw(load=modbus_req))
        pkts.append(Ether() / IP(src="10.0.0.6", dst="10.0.0.5") / TCP(sport=502, dport=50002, seq=400 + i * 11, flags="PA") / Raw(load=bytes.fromhex("0001000000050103020000")))
    flows = pcap.parse_pcap_file(_write_pcap(tmp_path / "mix.pcap", pkts))
    assert len(flows) == 3
    protos = {fl.flow: {fr.parsed.protocol for fr in fl.frames} for fl in flows}
    by_port = {k.split("->")[1].strip().split(":")[1]: v for k, v in protos.items()}
    assert by_port["9600"] == {"fins"}
    assert by_port["6000"] == {"melsec"}
    assert by_port["502"] == {"modbus"}
