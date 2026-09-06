"""DeviceDetector 真实 socket 端到端拓扑测试 (v0.4)。

与 tests/test_detect.py (假适配器钉逻辑) 互补: 本文件起**真实 TCP 服务**
(进程内 fake server + snap7 真实 server), 让 DeviceDetector 走完整三阶段
扫描 -> 指纹 -> 深读, 验证端到端识别结论。

- 全部 fake 用 port 0 (系统分配, 避免与本机已占用端口冲突);
- fake 服务复用 eval/fakes.py (eval 不是包, 按 test_eval.py 的 importlib
  方式按路径加载);
- snap7 用 python-snap7 原生 server (与 tests/e2e/test_cross_vendor.py 同
  布置方式, DB1 预置已知模式); 原生库启动失败时跳过 S7 相关断言而不 FAIL;
- 纪律: EOF 一律 return (eval/fakes.py 已内建); detect 用明确 ports 列表,
  不扫默认端口表, 全程 <10s。
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import time
from pathlib import Path

import pytest

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.protocols.detect import DeviceDetector

# 注册副作用 (与 server.py 同): DeviceDetector(adapters=None) 按注册表构建
import plctap.protocols.fins.adapter  # noqa: F401
import plctap.protocols.melsec.adapter  # noqa: F401
import plctap.protocols.modbus.adapter  # noqa: F401
import plctap.protocols.s7.adapter  # noqa: F401

_REPO_ROOT = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------ eval/fakes 加载


def _load_fakes():
    spec = importlib.util.spec_from_file_location("eval_fakes", _REPO_ROOT / "eval" / "fakes.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fakes_mod = _load_fakes()

# modbus 预置非零值: 地址 0 读回 (0+0)*3+preset
_MB_PRESET = 123
# snap7 DB1 预置模式 (与 sim_s7_server.py 一致): DB1.DBW0 = 0x1234
_S7_DB1_HEAD = bytes([0x12, 0x34, 0x56, 0x78, 0x41, 0xF0, 0x00, 0x00])
_S7_DB1_WORD0 = 0x1234


# ------------------------------------------------------------ 基础设施


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} not listening")


@pytest.fixture
def s7_port():
    """python-snap7 真实 server (in-process, 原生线程), DB1 预置已知模式。

    原生库缺失/启动失败 -> yield None (调用方对 S7 断言降级 + 末尾
    pytest.skip("snap7 native unavailable")), 不让整个文件 FAIL。
    """
    srv = None
    try:
        import snap7

        srv = snap7.Server(log=False)
        db1 = bytearray(100)
        db1[0:8] = _S7_DB1_HEAD
        srv.register_area(snap7.type.SrvArea.DB, 1, db1)
        port = _free_port()
        srv.start(tcp_port=port)
        _wait_port(port)
    except Exception:
        if srv is not None:
            try:
                srv.destroy()
            except Exception:
                pass
        yield None
        return
    try:
        yield port
    finally:
        try:
            srv.stop()
        finally:
            srv.destroy()


async def _start_topology(s7_port_val: int | None):
    """起一套五端口拓扑: modbus + s7(可选) + fins + melsec + echo。

    fake 全部 port=0 系统分配, 同一事件循环内起停; 返回 (fakes, ports)。
    """
    modbus = fakes_mod.FakeModbusServer(preset=_MB_PRESET)
    fins = fakes_mod.FakeFinsServer()
    melsec = fakes_mod.FakeMelsecServer()
    echo = fakes_mod.FakeEchoServer()
    started: list = []
    try:
        _, mb_port = await modbus.start()
        started.append(modbus)
        _, fins_port = await fins.start()
        started.append(fins)
        _, mc_port = await melsec.start()
        started.append(melsec)
        _, echo_port = await echo.start()
        started.append(echo)
    except BaseException:
        for f in started:
            await f.stop()
        raise
    fakes = {
        "modbus": modbus,
        "fins": fins,
        "melsec": melsec,
        "echo": echo,
    }
    ports = {
        "modbus": mb_port,
        "fins": fins_port,
        "melsec": mc_port,
        "echo": echo_port,
    }
    if s7_port_val is not None:
        ports["s7"] = s7_port_val
    return fakes, ports


def _detector() -> tuple[DeviceDetector, ConnectionPool]:
    pool = ConnectionPool(idle_timeout_sec=5.0)
    config = PlctapConfig(default_timeout_ms=1000)
    return DeviceDetector(pool, config), pool


async def _teardown(pool: ConnectionPool | None, fakes: dict) -> None:
    if pool is not None:
        await pool.close_all()
    for f in fakes.values():
        await f.stop()


# ------------------------------------------------------------ 主用例: deep=True


async def test_detect_full_topology_verified(s7_port):
    """五端口拓扑 deep=True: 四协议全部 verified + echo 落 unknown。"""
    fakes, ports = await _start_topology(s7_port)
    detector, pool = None, None
    try:
        detector, pool = _detector()
        ports_list = [ports["modbus"], ports["fins"], ports["melsec"]]
        if "s7" in ports:
            ports_list.append(ports["s7"])
        ports_list.append(ports["echo"])

        result = await detector.detect(host="127.0.0.1", ports=ports_list, deep=True)

        # 扫描阶段: 五端口全开放
        assert set(result.open_ports) == set(ports_list)
        assert result.closed_count == 0

        # 候选集合: modbus/fins/melsec (+s7), protocol -> port 一一对应
        want = {"modbus", "fins", "melsec"} | ({"s7"} if "s7" in ports else set())
        got = {c.protocol for c in result.candidates}
        assert got == want, f"candidates={result.candidates}"
        assert len(result.candidates) == len(want)
        by_proto = {c.protocol: c for c in result.candidates}
        for proto, port in ports.items():
            if proto == "echo":
                continue
            cand = by_proto[proto]
            assert cand.port == port, f"{proto}: {cand.port} != {port}"
            # deep 验证: verified + verified_read 非空
            assert cand.confidence == "verified", f"{proto}: {cand.confidence}"
            assert cand.verified_read, f"{proto}: verified_read 为空"
            regs = cand.verified_read.get("raw_registers")
            assert regs, f"{proto}: raw_registers 为空"
            # next_step 非空且含正确 host/port
            assert cand.next_step, f"{proto}: next_step 为空"
            assert "127.0.0.1" in cand.next_step, f"{proto}: {cand.next_step}"
            assert f"port={port}" in cand.next_step, f"{proto}: {cand.next_step}"

        # modbus 深读读到预置非零值 (addr0 = (0+0)*3 + 123)
        assert by_proto["modbus"].verified_read["raw_registers"] == [_MB_PRESET]
        if "s7" in ports:
            assert by_proto["s7"].verified_read["raw_registers"] == [_S7_DB1_WORD0]

        # echo 端口: 不出现在任何 candidate, 落 unknown_services 且 hint 含 start_listener
        assert all(c.port != ports["echo"] for c in result.candidates)
        assert [u["port"] for u in result.unknown_services] == [ports["echo"]]
        for u in result.unknown_services:
            assert "start_listener" in u["hint"], u
            assert u["probe_evidence"], u

        # network_assessment 非空字符串
        assert isinstance(result.network_assessment, str) and result.network_assessment

        if "s7" not in ports:
            pytest.skip("snap7 native unavailable")
    finally:
        await _teardown(pool, fakes)


# ------------------------------------------------------------ deep=False


async def test_detect_deep_false_high(s7_port):
    """deep=False: 指纹成立即 high, 不做深读, verified_read 全为 None。"""
    fakes, ports = await _start_topology(s7_port)
    detector, pool = None, None
    try:
        detector, pool = _detector()
        ports_list = [ports["modbus"], ports["fins"], ports["melsec"]]
        if "s7" in ports:
            ports_list.append(ports["s7"])
        ports_list.append(ports["echo"])

        result = await detector.detect(host="127.0.0.1", ports=ports_list, deep=False)

        want = {"modbus", "fins", "melsec"} | ({"s7"} if "s7" in ports else set())
        by_proto = {c.protocol: c for c in result.candidates}
        assert set(by_proto) == want, f"candidates={result.candidates}"
        for proto, port in ports.items():
            if proto == "echo":
                continue
            cand = by_proto[proto]
            assert cand.port == port
            assert cand.confidence == "high", f"{proto}: {cand.confidence}"
            assert cand.verified_read is None, f"{proto}: {cand.verified_read}"
        # echo 端口照旧落 unknown
        assert all(c.port != ports["echo"] for c in result.candidates)
        assert [u["port"] for u in result.unknown_services] == [ports["echo"]]

        if "s7" not in ports:
            pytest.skip("snap7 native unavailable")
    finally:
        await _teardown(pool, fakes)


# ------------------------------------------------------------ unknown-only


async def test_detect_unknown_only_echo():
    """只有未知回显服务: candidates 为空, unknown_services 恰含该端口。"""
    echo = fakes_mod.FakeEchoServer()
    _, echo_port = await echo.start()
    detector, pool = None, None
    try:
        detector, pool = _detector()
        result = await detector.detect(host="127.0.0.1", ports=[echo_port])
        assert result.candidates == [], f"candidates={result.candidates}"
        assert [u["port"] for u in result.unknown_services] == [echo_port]
        assert "start_listener" in result.unknown_services[0]["hint"]
        assert isinstance(result.network_assessment, str) and result.network_assessment
    finally:
        await _teardown(pool, {"echo": echo})


# ------------------------------------------------------------ 防回归: 事件循环不被饿死


async def test_topology_start_stop_is_clean():
    """起停一套 fake 拓扑不残留任务/连接 (EOF return 纪律的兜底观测)。"""
    fakes, ports = await _start_topology(None)
    try:
        assert len(ports) == 4
        # 各 fake 都能接受并处理一条真实连接 (modbus fc03 一问一答)
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["modbus"])
        import struct

        writer.write(struct.pack(">HHHBB", 1, 0, 6, 1, 3) + struct.pack(">HH", 0, 1))
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(7), 1.0)
        (length,) = struct.unpack_from(">H", head, 4)
        pdu = await asyncio.wait_for(reader.readexactly(length - 1), 1.0)
        assert pdu[0] == 3 and pdu[1] == 2
        writer.close()
    finally:
        await _teardown(None, fakes)
