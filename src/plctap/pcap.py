"""parse_pcap: Wireshark 导出 pcap 的结构化解析 (M3, PLAN.md 能力地图)。

做法: TCP 载荷按五元组流聚合 -> 每方向按 streams.py 分帧 -> 逐帧
parse_auto。这是"报文级深挖"对裸模型评测的碾压区 (大批量帧/冷门协议)。

简化边界 (注释即文档):
- 不做完整 TCP 重组: 短抓包按捕获顺序 + seq 连续性拼接; 乱序/重传跳过,
  seq 跳变记 gap 并从此处续接 (半帧会以 partial 形式浮出)
- scapy 是可选依赖 (pyproject eval extra), 未安装时给出明确安装提示
- protocol 缺省时按"完整帧数最多的协议"自动判别
"""

from __future__ import annotations

from pathlib import Path

from plctap import streams
from plctap.models import PcapFlow, PcapFrame, ParseResult
from plctap.protocols.auto import parse_auto

_PROTOCOLS = ("modbus", "fins", "melsec")


class _DirBuffer:
    """单方向载荷聚合: 按 seq 连续性拼接, 重传/乱序丢弃, 跳变记 gap。"""

    __slots__ = ("parts", "expected", "gaps")

    def __init__(self) -> None:
        self.parts: list[bytes] = []
        self.expected: int | None = None
        self.gaps = 0

    def add(self, seq: int, data: bytes) -> None:
        if not data:
            return
        if self.expected is None:
            self.expected = seq + len(data)
            self.parts.append(data)
            return
        if seq == self.expected:
            self.expected += len(data)
            self.parts.append(data)
        elif seq < self.expected:
            pass  # 重传/乱序重复, 丢弃
        else:
            self.gaps += 1
            self.expected = seq + len(data)
            self.parts.append(data)


def parse_pcap_file(path: str, protocol: str | None = None) -> list[PcapFlow]:
    """解析 pcap, 返回按流分组的帧序列。protocol 缺省自动判别。"""
    try:
        from scapy.all import rdpcap
    except ImportError as e:  # pragma: no cover - 依赖缺失提示
        raise RuntimeError(
            "parse_pcap requires scapy; install with: uv sync --extra eval (or pip install scapy)"
        ) from e

    pkts = rdpcap(str(Path(path).expanduser()))
    flows: dict[tuple, dict[str, _DirBuffer]] = {}
    for pkt in pkts:
        if not (pkt.haslayer("TCP") and pkt.haslayer("IP")):
            continue
        load = bytes(pkt["Raw"].load) if pkt.haslayer("Raw") else b""
        ip = pkt["IP"]
        tcp = pkt["TCP"]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        dirname = "forward"
        if key not in flows:
            rev = (ip.dst, tcp.dport, ip.src, tcp.sport)
            if rev in flows:
                key = rev
                dirname = "reverse"
            else:
                flows[key] = {"forward": _DirBuffer(), "reverse": _DirBuffer()}
        flows[key][dirname].add(tcp.seq, load)

    if protocol is None:
        protocol = _autodetect(flows)
    if protocol not in _PROTOCOLS:
        raise ValueError(f"unsupported protocol {protocol!r}; known: {_PROTOCOLS}")

    result: list[PcapFlow] = []
    for (src, sport, dst, dport), bufs in sorted(flows.items()):
        label = f"{src}:{sport} -> {dst}:{dport}"
        frames: list[PcapFrame] = []
        for name in ("forward", "reverse"):
            buf = bufs[name]
            payload = b"".join(buf.parts)
            complete, tail = streams.split_frames(protocol, payload)
            for fr in complete:
                frames.append(PcapFrame(frame_hex=fr.hex(), parsed=parse_auto(protocol, fr)))
            if tail:
                frames.append(
                    PcapFrame(
                        frame_hex=tail.hex(),
                        partial=True,
                        parsed=ParseResult(
                            protocol=protocol,
                            direction="resp",
                            valid=False,
                            errors=[f"partial tail frame, {len(tail)} bytes (capture cut?)"],
                        ),
                    )
                )
        if frames:
            result.append(PcapFlow(flow=label, frames=frames))
    return result


def _autodetect(flows: dict[tuple, dict[str, _DirBuffer]]) -> str:
    """按完整帧总数选协议 (能切出最多完整帧的协议最可能是真身)。"""
    best, best_proto = 0, None
    for proto in _PROTOCOLS:
        total = 0
        for bufs in flows.values():
            for name in ("forward", "reverse"):
                payload = b"".join(bufs[name].parts)
                complete, _ = streams.split_frames(proto, payload)
                total += len(complete)
        if total > best:
            best, best_proto = total, proto
    if best_proto is None:
        raise ValueError("no complete frames found in capture; specify protocol explicitly")
    return best_proto
