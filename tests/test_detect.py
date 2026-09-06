"""DeviceDetector 单测 (v0.4): 注入假适配器覆盖识别全流程。

网络只碰本机: open 用真实 127.0.0.1 listener; 未监听端口在 Windows 上
可能表现为 timeout 而非 refused (防火墙丢 SYN), 断言只接受两者之一;
置信度/固定文案/排序/next_step 等纯逻辑用可编程假适配器钉死
(评测语料对齐, 文案逐字符断言)。
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import ProbeResult, ReadResult, Target
from plctap.protocols import detect as detect_mod
from plctap.protocols.detect import DeviceDetector


# ------------------------------------------------------------ 测试替身


class FakeAdapter:
    """可编程 probe/read 测试替身: 按构造参数返回或抛错, 并留调用痕迹。"""

    def __init__(
        self,
        name: str,
        *,
        probe_result: ProbeResult | None = None,
        probe_error: Exception | None = None,
        read_result: ReadResult | None = None,
        read_error: Exception | None = None,
    ) -> None:
        self.name = name
        self.probe_result = probe_result
        self.probe_error = probe_error
        self.read_result = read_result
        self.read_error = read_error
        self.probe_targets: list[Target] = []
        self.read_calls: list[tuple[int, int, dict]] = []

    async def probe(self, target: Target) -> ProbeResult:
        self.probe_targets.append(target)
        if self.probe_error is not None:
            raise self.probe_error
        return self.probe_result  # type: ignore[return-value]

    async def read(
        self, target: Target, address: int = 0, count: int = 1, **kwargs
    ) -> ReadResult | None:
        self.read_calls.append((address, count, kwargs))
        if self.read_error is not None:
            raise self.read_error
        return self.read_result


class SlowAdapter(FakeAdapter):
    """probe 永远超出指纹预算的假适配器 (验证 wait_for 裁剪)。"""

    async def probe(self, target: Target) -> ProbeResult:
        self.probe_targets.append(target)
        await asyncio.sleep(1.0)
        return ProbeResult(reachable=True)


class NullServer:
    """只 accept 不回话的 TCP listener: 供阶段0 扫描判 open (连上即断也认)。"""

    def __init__(self) -> None:
        self.server: asyncio.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await reader.read()  # 挂住连接, 对端关闭即退出
        except (ConnectionError, TimeoutError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


@pytest.fixture
async def null_server():
    s = NullServer()
    await s.start()
    yield s
    await s.stop()


def make_detector(adapters: dict) -> DeviceDetector:
    return DeviceDetector(
        ConnectionPool(idle_timeout_sec=60, max_per_target=2),
        PlctapConfig(default_timeout_ms=500),
        adapters,
    )


def make_read_result(*registers: int) -> ReadResult:
    return ReadResult(
        target=Target(protocol="fake", host="127.0.0.1", port=0),
        address=0,
        request_frame="",
        raw_registers=list(registers),
        elapsed_ms=0,
    )


def unused_port() -> int:
    """借一个当前空闲端口 (存在极小竞态, 测试可接受)。"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------ 置信度映射


async def test_confidence_normal_probe_is_high(null_server):
    """reachable + 无 failure_class → high, 证据用 modbus 固定文案。"""
    fake = FakeAdapter("modbus", probe_result=ProbeResult(reachable=True))
    r = await make_detector({"modbus": fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=False
    )
    assert [(c.protocol, c.port, c.confidence) for c in r.candidates] == [
        ("modbus", null_server.port, "high")
    ]
    assert r.candidates[0].evidence == [
        "MBAP 响应自洽 (tid 回显, proto_id=0, length 合理)"
    ]
    assert r.candidates[0].verified_read is None
    assert fake.probe_targets == [
        Target(protocol="modbus", host="127.0.0.1", port=null_server.port)
    ]
    assert r.unknown_services == []


async def test_confidence_exception_response_is_high(null_server):
    """exception_response 也算 high (设备在线且回协议语义), 证据带异常码。"""
    fake = FakeAdapter(
        "modbus",
        probe_result=ProbeResult(
            reachable=True, failure_class="exception_response", exception_code=0x02
        ),
    )
    r = await make_detector({"modbus": fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=False
    )
    c = r.candidates[0]
    assert c.confidence == "high"
    # {code:#x} 渲染: 0x02 -> "0x2"
    assert c.evidence == [
        "Modbus 异常响应 (fc|0x80, exception_code=0x2) — 设备在线且回 Modbus 语义"
    ]


async def test_non_modbus_exception_appends_code_line(null_server):
    """未配异常文案模板的协议: 固定文案后附加 exception_code 行。"""
    fake = FakeAdapter(
        "s7",
        probe_result=ProbeResult(
            reachable=True, failure_class="exception_response", exception_code=0xC1
        ),
    )
    r = await make_detector({"s7": fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=False
    )
    assert r.candidates[0].evidence == [
        "TPKT+COTP 连接确认 (CC), S7comm 结构特征成立",
        "exception_code=0xc1",
    ]


async def test_unreachable_probe_not_candidate(null_server):
    """reachable=False 不成候选, 端口落 unknown_services (failure_class 摘要)。"""
    fake = FakeAdapter(
        "modbus", probe_result=ProbeResult(reachable=False, failure_class="timeout")
    )
    r = await make_detector({"modbus": fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=False
    )
    assert r.candidates == []
    assert r.unknown_services == [
        {
            "port": null_server.port,
            "probe_evidence": "modbus=timeout",
            "hint": "设备可能仅主动外连或使用未支持协议; 可用 start_listener 在该端口钓帧分析",
        }
    ]


async def test_probe_error_and_budget_timeout_notes(null_server):
    """probe 抛错/超预算都不炸整轮识别, 摘要里如实录标签。"""
    err = FakeAdapter("modbus", probe_error=RuntimeError("unexpected eof"))
    r = await make_detector({"modbus": err}).detect(
        "127.0.0.1", ports=[null_server.port], timeout_ms=200, deep=False
    )
    assert r.unknown_services[0]["probe_evidence"] == "modbus=RuntimeError: unexpected eof"

    slow = SlowAdapter("modbus")
    r = await make_detector({"modbus": slow}).detect(
        "127.0.0.1", ports=[null_server.port], timeout_ms=100, deep=False
    )
    assert slow.probe_targets, "预算裁剪发生在 probe 已被调用之后"
    assert r.unknown_services[0]["probe_evidence"] == "modbus=timeout"


# ------------------------------------------------------------ 排序与端口先验


async def test_sort_confidence_desc_then_port_prior(monkeypatch):
    """verified 排 high 之前; 同级先验匹配端口优先 (稳定排序保序)。"""
    s1, s2 = NullServer(), NullServer()
    await s1.start()
    await s2.start()
    try:
        # s1 对 fins 有先验; modbus 深读成功升 verified, fins 深读失败保 high
        monkeypatch.setitem(detect_mod.PORT_PRIORS, s1.port, "fins")
        adapters = {
            "modbus": FakeAdapter(
                "modbus",
                probe_result=ProbeResult(reachable=True),
                read_result=make_read_result(7),
            ),
            "fins": FakeAdapter(
                "fins",
                probe_result=ProbeResult(reachable=True),
                read_error=RuntimeError("denied"),
            ),
        }
        r = await make_detector(adapters).detect(
            "127.0.0.1", ports=[s1.port, s2.port], deep=True
        )
        assert [(c.protocol, c.port, c.confidence) for c in r.candidates] == [
            ("modbus", s1.port, "verified"),
            ("modbus", s2.port, "verified"),
            ("fins", s1.port, "high"),  # 先验匹配端口优先
            ("fins", s2.port, "high"),
        ]
    finally:
        await s1.stop()
        await s2.stop()


# ------------------------------------------------------------ deep 验证


async def test_deep_upgrade_verified_and_truncate(null_server):
    """deep 读成功 → verified, verified_read 只保留前 10 个寄存器。"""
    fake = FakeAdapter(
        "modbus",
        probe_result=ProbeResult(reachable=True),
        read_result=make_read_result(*range(12)),
    )
    r = await make_detector({"modbus": fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=True
    )
    c = r.candidates[0]
    assert c.confidence == "verified"
    assert c.verified_read == {"raw_registers": list(range(10))}
    assert fake.read_calls == [(0, 1, {})]


async def test_deep_failure_keeps_high(null_server):
    """deep 读任何异常 → evidence 留痕, 保持 high, verified_read 为空。"""
    fake = FakeAdapter(
        "modbus",
        probe_result=ProbeResult(reachable=True),
        read_error=RuntimeError("connection reset by peer"),
    )
    r = await make_detector({"modbus": fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=True
    )
    c = r.candidates[0]
    assert c.confidence == "high"
    assert c.verified_read is None
    assert c.evidence == [
        "MBAP 响应自洽 (tid 回显, proto_id=0, length 合理)",
        "deep read failed: connection reset by peer",
    ]


async def test_deep_false_skips_verification_read(null_server):
    """deep=False 不发验证读, 候选停在 high。"""
    fake = FakeAdapter(
        "modbus",
        probe_result=ProbeResult(reachable=True),
        read_result=make_read_result(1),
    )
    r = await make_detector({"modbus": fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=False
    )
    assert fake.read_calls == []
    assert r.candidates[0].confidence == "high"
    assert r.candidates[0].verified_read is None


@pytest.mark.parametrize("protocol", ["s7", "fins", "melsec"])
async def test_deep_read_params_come_from_registry(null_server, protocol):
    """各协议最小读的地址/数量/选项来自注册表 (契约冻结), 逐项核对实参。"""
    fake = FakeAdapter(
        protocol,
        probe_result=ProbeResult(reachable=True),
        read_result=make_read_result(0),
    )
    await make_detector({protocol: fake}).detect(
        "127.0.0.1", ports=[null_server.port], deep=True
    )
    expected = {
        "s7": (0, 2, {"area": "DB", "db_number": 1}),
        "fins": (0, 1, {"area": "DM"}),
        "melsec": (0, 2, {"device": "D"}),
    }[protocol]
    assert fake.read_calls == [expected]


# ------------------------------------------------------------ next_step


@pytest.mark.parametrize("protocol", ["modbus", "s7", "fins", "melsec"])
async def test_next_step_exact_text(null_server, protocol):
    """next_step 模板逐字符断言 (评测语料对齐, 不得改写)。"""
    fake = FakeAdapter(
        protocol,
        probe_result=ProbeResult(reachable=True),
        read_result=make_read_result(1),
    )
    port = null_server.port
    r = await make_detector({protocol: fake}).detect(
        "127.0.0.1", ports=[port], deep=False
    )
    expected = {
        "modbus": (
            f"plc_read(protocol='modbus', host='127.0.0.1', port={port}, "
            "address=0, count=10)"
        ),
        "s7": (
            f"plc_read(protocol='s7', host='127.0.0.1', port={port}, address=0, count=4, "
            "datatype='uint16', options={'area': 'DB', 'db_number': 1})"
        ),
        "fins": (
            f"plc_read(protocol='fins', host='127.0.0.1', port={port}, address=0, count=10, "
            "options={'area': 'DM'})"
        ),
        "melsec": (
            f"plc_read(protocol='melsec', host='127.0.0.1', port={port}, address=0, count=10, "
            "options={'device': 'D'})"
        ),
    }[protocol]
    assert r.candidates[0].next_step == expected


# ------------------------------------------------------------ unknown_services 与汇总


async def test_unknown_services_and_network_assessment(null_server):
    """开放但无可达候选 → unknown_services; refused/timeout 统一计 closed。"""
    adapters = {
        "modbus": FakeAdapter(
            "modbus", probe_result=ProbeResult(reachable=False, failure_class="timeout")
        ),
        "fins": FakeAdapter(
            "fins",
            probe_result=ProbeResult(reachable=False, failure_class="connection_refused"),
        ),
    }
    r = await make_detector(adapters).detect(
        "127.0.0.1", ports=[null_server.port, unused_port()], deep=False
    )
    assert r.open_ports == [null_server.port]
    assert r.closed_count == 1
    assert r.unknown_services == [
        {
            "port": null_server.port,
            "probe_evidence": "modbus=timeout; fins=connection_refused",
            "hint": "设备可能仅主动外连或使用未支持协议; 可用 start_listener 在该端口钓帧分析",
        }
    ]
    assert r.network_assessment == "1 端口关闭/超时, 1 端口开放, 1 端口开放未识别, 0 个协议候选"


# ------------------------------------------------------------ 端口扫描三分类


class _FakeWriter:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


async def test_scan_one_classification_monkeypatched(monkeypatch):
    """refused/timeout/open 三分类: 注入异常钉死前两类, open 用假 writer。"""
    det = make_detector({})

    async def _refused(*args, **kwargs):
        raise ConnectionRefusedError()

    async def _timeout(*args, **kwargs):
        raise TimeoutError()

    opened: list[_FakeWriter] = []

    async def _open(*args, **kwargs):
        w = _FakeWriter()
        opened.append(w)
        return None, w

    monkeypatch.setattr(detect_mod.asyncio, "open_connection", _refused)
    assert await det._scan_one("127.0.0.1", 1) == "refused"
    monkeypatch.setattr(detect_mod.asyncio, "open_connection", _timeout)
    assert await det._scan_one("127.0.0.1", 1) == "timeout"
    monkeypatch.setattr(detect_mod.asyncio, "open_connection", _open)
    assert await det._scan_one("127.0.0.1", 1) == "open"
    assert opened[0].closed, "open 端口应立即关闭探测连接"


async def test_scan_real_listener_open_and_closed(null_server):
    """真实 127.0.0.1 listener 判 open; 未监听端口 refused/timeout 都计 closed。

    Windows 防火墙对未监听端口可能丢 SYN (表现为 timeout), 这里不断言
    单端口分类, 只断言计入 closed_count (平台无关)。
    """
    r = await make_detector({}).detect(
        "127.0.0.1", ports=[null_server.port, unused_port()], deep=False
    )
    assert r.open_ports == [null_server.port]
    assert r.closed_count == 1
    # 零协议注入: 开放端口一律落 unknown_services (摘要为空)
    assert r.unknown_services[0]["port"] == null_server.port
    assert r.network_assessment == "1 端口关闭/超时, 1 端口开放, 1 端口开放未识别, 0 个协议候选"


# ------------------------------------------------------------ 输入边界


async def test_empty_ports_returns_empty_result():
    """ports=[] 是合法输入: 空结果, 不报错。"""
    fake = FakeAdapter("modbus", probe_result=ProbeResult(reachable=True))
    r = await make_detector({"modbus": fake}).detect("127.0.0.1", ports=[], deep=False)
    assert r.scanned_ports == []
    assert r.open_ports == []
    assert r.candidates == []
    assert r.unknown_services == []
    assert r.closed_count == 0
    assert r.network_assessment == "0 端口关闭/超时, 0 端口开放, 0 端口开放未识别, 0 个协议候选"


async def test_default_scan_ports_when_none(null_server, monkeypatch):
    """ports=None 运行时取 DEFAULT_SCAN_PORTS (便于环境覆盖)。"""
    monkeypatch.setattr(detect_mod, "DEFAULT_SCAN_PORTS", [null_server.port])
    r = await make_detector({}).detect("127.0.0.1", deep=False)
    assert r.scanned_ports == [null_server.port]
    assert r.open_ports == [null_server.port]
