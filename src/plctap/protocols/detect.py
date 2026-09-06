"""设备自动识别 (v0.4): 端口扫描 -> 协议指纹 -> 深读验证 -> next_step。

三阶段全程只读: 阶段0 只做 TCP 连接即断开; 阶段1 复用各协议
adapter.probe (仅握手帧); deep 阶段对 high 候选补一次最小读帧。
识别 ≠ 可访问: 指纹成立不代表应用层放行 (如 S7 PUT/GET 关闭时识别
成功但读 DB 失败), 因此 deep 失败只留痕降级, 不作为错误抛出。

证据文案/深读参数/next_step 模板收敛在 _PROFILES 注册表: v0.5 新协议
接入 = 适配器 register + _PROFILES 加一条, DeviceDetector 逻辑零改动。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import ProbeResult, ReadResult, Target
from plctap.protocols.base import ProtocolAdapter, adapter_for, known_protocols

DEFAULT_SCAN_PORTS = [102, 502, 2000, 44818, 5007, 6000, 9600, 9601]

# 端口先验: 仅用于同级候选排序 (先验匹配端口优先), 不参与置信度评分。
# 44818 是 EtherNet/IP 规范端口, 与本仓库 melsec 的 default_port 撞号 ——
# 纯属数字巧合, 不构成 melsec 先验, 故必须为 None (v0.4 不支持
# EtherNet/IP, 该端口只能靠 unknown_services + start_listener 兜底)。
PORT_PRIORS: dict[int, str | None] = {
    102: "s7",
    502: "modbus",
    2000: "melsec",
    44818: None,
    5007: "melsec",
    6000: "melsec",
    9600: "fins",
    9601: "fins",
}

CONFIDENCE_ORDER = {"verified": 4, "high": 3, "medium": 2, "low": 1}

# unknown_services 的固定提示 (评测语料对齐, 不得改写)
_UNKNOWN_HINT = (
    "设备可能仅主动外连或使用未支持协议; 可用 start_listener 在该端口钓帧分析"
)

# deep 验证读签名: (adapter, target) -> ReadResult
DeepReadFn = Callable[[ProtocolAdapter, Target], Awaitable[ReadResult]]


# ------------------------------------------------------------ deep 验证读

async def _deep_read_modbus(ad: ProtocolAdapter, t: Target) -> ReadResult:
    """最小读: 1 个保持寄存器。"""
    return await ad.read(t, address=0, count=1)


async def _deep_read_s7(ad: ProtocolAdapter, t: Target) -> ReadResult:
    """最小读: DB1.DBW0 起 2 字节 (S7 count 语义为字节数)。"""
    return await ad.read(t, address=0, count=2, area="DB", db_number=1)


async def _deep_read_fins(ad: ProtocolAdapter, t: Target) -> ReadResult:
    """最小读: DM 区 1 字。"""
    return await ad.read(t, address=0, count=1, area="DM")


async def _deep_read_melsec(ad: ProtocolAdapter, t: Target) -> ReadResult:
    """最小读: D 软元件 2 字 (部分从站实现对 1 字读有越界 bug)。"""
    return await ad.read(t, address=0, count=2, device="D")


@dataclass(frozen=True)
class _Profile:
    """单协议识别配置 (注册表条目): 证据文案 + 深读参数 + next_step 模板。

    未注册 _PROFILES 的协议仍会被 probe (走 _fallback_profile 的通用
    文案), 但不会有精确证据/next_step —— 兜底保证识别不漏协议。
    """

    evidence: str  # probe 正常完成 (failure_class=None) 的固定文案
    # exception_response 文案模板 ({code:#x} 占位); None = 通用附加行
    exception_evidence: str | None
    deep_read: DeepReadFn  # 最小验证读 (地址/数量按协议语义取最小)
    next_step: str  # next_step 模板, .format(host=..., port=...) 后可直接执行


_PROFILES: dict[str, _Profile] = {
    "modbus": _Profile(
        evidence="MBAP 响应自洽 (tid 回显, proto_id=0, length 合理)",
        exception_evidence=(
            "Modbus 异常响应 (fc|0x80, exception_code={code:#x}) — 设备在线且回 Modbus 语义"
        ),
        deep_read=_deep_read_modbus,
        next_step="plc_read(protocol='modbus', host='{host}', port={port}, address=0, count=10)",
    ),
    "s7": _Profile(
        evidence="TPKT+COTP 连接确认 (CC), S7comm 结构特征成立",
        exception_evidence=None,
        deep_read=_deep_read_s7,
        next_step=(
            "plc_read(protocol='s7', host='{host}', port={port}, address=0, count=4, "
            "datatype='uint16', options={{'area': 'DB', 'db_number': 1}})"
        ),
    ),
    "fins": _Profile(
        evidence="FINS/TCP 魔数验证通过, 节点连接确认",
        exception_evidence=None,
        deep_read=_deep_read_fins,
        next_step=(
            "plc_read(protocol='fins', host='{host}', port={port}, address=0, count=10, "
            "options={{'area': 'DM'}})"
        ),
    ),
    "melsec": _Profile(
        evidence="MC 副头部回显正确 (D0 00), 端结码字段自洽",
        exception_evidence=None,
        deep_read=_deep_read_melsec,
        next_step=(
            "plc_read(protocol='melsec', host='{host}', port={port}, address=0, count=10, "
            "options={{'device': 'D'}})"
        ),
    ),
}


def _fallback_profile(name: str) -> _Profile:
    """未注册 _PROFILES 的协议兜底 (v0.5 漏注册也能识别, 文案为通用版)。"""
    return _Profile(
        evidence=f"{name} probe 可达",
        exception_evidence=None,
        deep_read=lambda ad, t: ad.read(t, address=0, count=1),
        next_step=(
            f"plc_read(protocol='{name}', host='{{host}}', port={{port}}, "
            "address=0, count=1)"
        ),
    )


def _assessment(
    closed_count: int, open_count: int, unknown_count: int, candidate_count: int
) -> str:
    """network_assessment 固定模板 (评测语料对齐, 不得改写)。"""
    return (
        f"{closed_count} 端口关闭/超时, {open_count} 端口开放, "
        f"{unknown_count} 端口开放未识别, {candidate_count} 个协议候选"
    )


@dataclass
class DetectEvidence:
    """单个 (端口, 协议) 候选的识别证据链。"""

    protocol: str
    port: int
    confidence: str  # verified|high|medium|low
    evidence: list[str]
    verified_read: dict | None = None
    next_step: str | None = None


@dataclass
class DetectResult:
    """detect_device 输出: 扫描/指纹/验证三阶段的结构化汇总。

    candidates 按 confidence 降序, 同级先验匹配端口优先; unknown_services
    保留"开放但无可达候选"的端口 (识别不出 ≠ 直接判死)。
    """

    host: str
    scanned_ports: list[int]
    open_ports: list[int]
    candidates: list[DetectEvidence]
    unknown_services: list[dict]
    closed_count: int
    network_assessment: str
    elapsed_ms: int


class DeviceDetector:
    """协议自动识别器: 扫描 -> 指纹 -> 深读, 全程只读 (握手帧 + 最小读帧)。

    adapters 注入点: 键即参与识别的协议集合 (单测注入假适配器 / 裁剪
    协议, 传空 dict = 只扫描不指纹); 缺省取全部已注册适配器。
    """

    SCAN_CONNECT_TIMEOUT_SEC = 0.5  # 阶段0 单端口连接预算
    FINGERPRINT_TIMEOUT_SEC = 0.8  # 阶段1 单协议 probe 预算 (未显式传 timeout_ms 时)

    def __init__(
        self,
        pool: ConnectionPool,
        config: PlctapConfig,
        adapters: dict[str, ProtocolAdapter] | None = None,
    ) -> None:
        self.pool = pool
        self.config = config
        self._adapters = (
            adapters
            if adapters is not None
            else {name: adapter_for(name)(pool, config) for name in known_protocols()}
        )

    # ------------------------------------------------------------ 主流程

    async def detect(
        self,
        host: str,
        ports: list[int] | None = None,
        timeout_ms: int | None = None,
        deep: bool = True,
    ) -> DetectResult:
        """三阶段识别: 并发扫描 -> 并发指纹 -> (可选) deep 验证读。"""
        started = time.perf_counter()
        scan_ports = list(ports) if ports is not None else list(DEFAULT_SCAN_PORTS)
        open_ports = await self._scan(host, scan_ports)
        closed_count = len(scan_ports) - len(open_ports)
        budget = (
            timeout_ms / 1000 if timeout_ms is not None else self.FINGERPRINT_TIMEOUT_SEC
        )
        probes = await self._fingerprint_all(host, open_ports, budget)
        candidates, unknown = self._collect(host, open_ports, probes)
        if deep:
            await self._verify_deep(host, candidates)
        # verified > high; 同级先验匹配端口优先 (稳定排序保持端口/协议次序)
        candidates.sort(
            key=lambda c: (
                -CONFIDENCE_ORDER.get(c.confidence, 0),
                0 if PORT_PRIORS.get(c.port) == c.protocol else 1,
            )
        )
        return DetectResult(
            host=host,
            scanned_ports=scan_ports,
            open_ports=open_ports,
            candidates=candidates,
            unknown_services=unknown,
            closed_count=closed_count,
            network_assessment=_assessment(
                closed_count, len(open_ports), len(unknown), len(candidates)
            ),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )

    # ------------------------------------------------------------ 阶段0 扫描

    async def _scan(self, host: str, ports: list[int]) -> list[int]:
        """并发 TCP 连接探测, 只保留开放端口 (顺序与入参一致)。"""
        if not ports:
            return []
        statuses = await asyncio.gather(*(self._scan_one(host, p) for p in ports))
        return [p for p, status in zip(ports, statuses) if status == "open"]

    async def _scan_one(self, host: str, port: int) -> str:
        """单端口三分类: open (连上即关) / refused / timeout。"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), self.SCAN_CONNECT_TIMEOUT_SEC
            )
        except ConnectionRefusedError:
            return "refused"
        except TimeoutError:  # OSError 子类, 必须先于 OSError 匹配
            return "timeout"
        except OSError:
            return "refused"  # 网络不可达等与 refused 同属"连接未建立"
        writer.close()  # 只探测不通信, 立即释放
        return "open"

    # ------------------------------------------------------------ 阶段1 指纹

    async def _fingerprint_all(
        self, host: str, open_ports: list[int], budget: float
    ) -> dict[tuple[int, str], tuple[ProbeResult | None, str]]:
        """每个开放端口并发跑全部协议 probe: (port, protocol) -> (结果, 失败说明)。"""
        pairs = [(p, name) for p in open_ports for name in self._adapters]
        results = await asyncio.gather(
            *(self._fingerprint(host, p, name, budget) for p, name in pairs)
        )
        return dict(zip(pairs, results))

    async def _fingerprint(
        self, host: str, port: int, name: str, budget: float
    ) -> tuple[ProbeResult | None, str]:
        """单协议 probe, 预算内未完成视作该协议不可达 (返回 None + 说明)。"""
        target = Target(protocol=name, host=host, port=port)
        try:
            return (await asyncio.wait_for(self._adapters[name].probe(target), budget)), ""
        except TimeoutError:
            return None, "timeout"
        except Exception as e:
            # 扫描面对未知设备, 单协议炸掉不得中断整轮识别; 异常如实录进摘要
            return None, f"{type(e).__name__}: {e}"

    # ------------------------------------------------------------ 证据整理

    def _profile(self, name: str) -> _Profile:
        return _PROFILES.get(name) or _fallback_profile(name)

    def _collect(
        self,
        host: str,
        open_ports: list[int],
        probes: dict[tuple[int, str], tuple[ProbeResult | None, str]],
    ) -> tuple[list[DetectEvidence], list[dict]]:
        """reachable=True 的 probe 成候选, 其余端口落 unknown_services。"""
        candidates: list[DetectEvidence] = []
        unknown: list[dict] = []
        for port in open_ports:
            port_candidates: list[DetectEvidence] = []
            summary: list[str] = []
            for name in self._adapters:
                result, note = probes[(port, name)]
                summary.append(f"{name}={self._failure_label(result, note)}")
                if result is None or not result.reachable:
                    continue
                profile = self._profile(name)
                port_candidates.append(
                    DetectEvidence(
                        protocol=name,
                        port=port,
                        # exception_response 也 high: 设备在线且回协议语义,
                        # 应用层配置问题交给 deep 验证与后续 plc_read 暴露
                        confidence="high",
                        evidence=self._evidence_for(profile, result),
                        next_step=profile.next_step.format(host=host, port=port),
                    )
                )
            if port_candidates:
                candidates.extend(port_candidates)
            else:
                unknown.append(
                    {
                        "port": port,
                        "probe_evidence": "; ".join(summary),
                        "hint": _UNKNOWN_HINT,
                    }
                )
        return candidates, unknown

    @staticmethod
    def _failure_label(result: ProbeResult | None, note: str) -> str:
        """unknown_services 摘要用的单协议标签 (failure_class 或失败说明)。"""
        if result is None:
            return note or "no_reply"
        return result.failure_class or "reachable"

    @staticmethod
    def _evidence_for(profile: _Profile, result: ProbeResult) -> list[str]:
        """按 probe 结果取固定证据文案 (评测语料对齐, 不得改写)。"""
        if result.failure_class == "exception_response":
            code = result.exception_code
            if profile.exception_evidence is not None and isinstance(code, int):
                return [profile.exception_evidence.format(code=code)]
            if isinstance(code, int):
                return [profile.evidence, f"exception_code={code:#x}"]
            return [profile.evidence, f"exception_code={code}"]
        return [profile.evidence]

    # ------------------------------------------------------------ deep 验证

    async def _verify_deep(self, host: str, candidates: list[DetectEvidence]) -> None:
        """high 候选并发做一次最小读: 成功升级 verified, 任何异常留痕保持 high。"""
        highs = [c for c in candidates if c.confidence == "high"]
        if not highs:
            return

        async def _one(cand: DetectEvidence) -> None:
            profile = self._profile(cand.protocol)
            target = Target(protocol=cand.protocol, host=host, port=cand.port)
            try:
                result = await profile.deep_read(self._adapters[cand.protocol], target)
                verified = {"raw_registers": result.raw_registers[:10]}
            except Exception as e:  # 深读失败是证据不是错误 (识别 ≠ 可访问)
                cand.evidence.append(f"deep read failed: {e}")
                return
            cand.confidence = "verified"
            cand.verified_read = verified

        await asyncio.gather(*(_one(c) for c in highs))
