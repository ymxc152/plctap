"""parse_pcap: Wireshark 导出 pcap 的结构化解析 (M3, PLAN.md 能力地图)。

做法: TCP 载荷按五元组流聚合 -> 每方向按 streams.py 分帧 -> 逐帧
parse_auto。这是"报文级深挖"对裸模型评测的碾压区 (大批量帧/冷门协议)。

简化边界 (注释即文档):
- 不做完整 TCP 重组: 短抓包按捕获顺序 + seq 连续性拼接; 乱序/重传跳过,
  seq 跳变记 gap 并从此处续接 (半帧会以 partial 形式浮出)
- scapy 是可选依赖 (pyproject eval extra), 未安装时给出明确安装提示
- protocol 缺省时**逐流**判别 (每条 TCP 流独立按"该流完整帧数最多的协议"
  选型, 混合协议抓包互不干扰); 单流切不出完整帧时退回全局最优
- 输出有 token 预算上限 (_PCAP_OUTPUT_BUDGET_BYTES): 超出时按流序/帧序
  截断, 末尾 sentinel 流带 truncated 标记与 total 计数 (tests/
  test_token_budget.py 钉住)
"""

from __future__ import annotations

from pathlib import Path

from plctap import streams
from plctap.models import PcapFlow, PcapFrame, ParseResult
from plctap.protocols.auto import parse_auto

_PROTOCOLS = ("modbus", "fins", "melsec")

# 单次调用的输出预算 (v0.6 token 预算, tests/test_token_budget.py 钉住):
# 装帧时按 PcapFrame 序列化字节累加, 放不下即停, 截断以 sentinel 流收尾
# (flow 以 "truncated:" 开头, 带 total/shown 计数)。64KB ≈ 80 帧 modbus
# 均价帧, Agent 可逐帧消化; 合法最大单帧 (FINS/MELSEC 16KB 读满数据)
# 解析实测约 59KB, 必然放得下 —— 正常抓包不会出现 0 帧输出。
_PCAP_OUTPUT_BUDGET_BYTES = 64 * 1024


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
    """解析 pcap, 返回按流分组的帧序列。protocol 缺省自动判别。

    输出受 _PCAP_OUTPUT_BUDGET_BYTES 预算约束 (MCP token 预算): 按流序/
    帧序装帧, 超出即停。截断时末尾追加一条 sentinel 流: flow 以
    "truncated:" 开头并带 total/shown 计数, frames 为空 —— 拿其余帧请
    用 protocol= 过滤或拆分 pcap 后再解析。
    """
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

    if protocol is not None and protocol not in _PROTOCOLS:
        raise ValueError(f"unsupported protocol {protocol!r}; known: {_PROTOCOLS}")

    # 第一遍: 逐流切帧 (便宜, 不 parse), 统计总帧数并暂存切帧结果;
    # parse_auto 才是贵的那步, 留到第二遍按预算装, 不为装不下的帧白算
    flow_labels: list[str] = []
    flow_protos: list[str] = []
    flow_chunks: list[list[tuple[bytes, bool]]] = []  # (帧字节, 是否尾部半帧)
    total = 0
    for (src, sport, dst, dport), bufs in sorted(flows.items()):
        label = f"{src}:{sport} -> {dst}:{dport}"
        # 逐流判别: 混合协议 pcap 中每条流独立选型 (FINS 流不再被 modbus 淹没)
        flow_proto = protocol or _autodetect_flow(bufs)
        chunk: list[tuple[bytes, bool]] = []
        for name in ("forward", "reverse"):
            buf = bufs[name]
            payload = b"".join(buf.parts)
            complete, tail = streams.split_frames(flow_proto, payload)
            chunk.extend((fr, False) for fr in complete)
            if tail:
                chunk.append((tail, True))  # 尾部半帧也计入 total (partial 在第二遍打标)
        flow_labels.append(label)
        flow_protos.append(flow_proto)
        flow_chunks.append(chunk)
        total += len(chunk)

    # 第二遍: 按预算装帧。序列化大小用 model_dump_json 精确计量,
    # 保证"预算内"是硬数字而不是估算
    shown = 0
    used = 0
    truncated = False
    result: list[PcapFlow] = []
    for label, flow_proto, chunk in zip(flow_labels, flow_protos, flow_chunks):
        frames: list[PcapFrame] = []
        for data, is_tail in chunk:
            if is_tail:
                pf = PcapFrame(
                    frame_hex=data.hex(),
                    partial=True,
                    parsed=ParseResult(
                        protocol=flow_proto,
                        direction="resp",
                        valid=False,
                        errors=[f"partial tail frame, {len(data)} bytes (capture cut?)"],
                    ),
                )
            else:
                pf = PcapFrame(frame_hex=data.hex(), parsed=parse_auto(flow_proto, data))
            sz = len(pf.model_dump_json())
            if used + sz > _PCAP_OUTPUT_BUDGET_BYTES:
                truncated = True
                break
            used += sz
            frames.append(pf)
            shown += 1
        if frames:
            result.append(PcapFlow(flow=label, frames=frames))
        if truncated:
            break
    if truncated:
        # sentinel 流: truncated 标记 + total/shown 计数 (frames 为空,
        # 不伪造帧数据; flow 前缀 "truncated:" 便于 Agent 快速识别)
        result.append(PcapFlow(
            flow=(
                f"truncated: total {total} frames, showing first {shown} "
                f"(output budget {_PCAP_OUTPUT_BUDGET_BYTES} bytes); "
                "use protocol= filter or split the pcap for the rest"
            ),
            frames=[],
        ))
    return result


def _autodetect_flow(bufs: dict[str, _DirBuffer]) -> str:
    """单流判别: 该流两个方向里完整帧数最多的协议即真身。"""
    best, best_proto = 0, None
    for proto in _PROTOCOLS:
        total = 0
        for name in ("forward", "reverse"):
            payload = b"".join(bufs[name].parts)
            complete, _ = streams.split_frames(proto, payload)
            total += len(complete)
        if total > best:
            best, best_proto = total, proto
    if best_proto is None:
        raise ValueError(
            "no complete frames found in capture flow; specify protocol explicitly"
        )
    return best_proto
