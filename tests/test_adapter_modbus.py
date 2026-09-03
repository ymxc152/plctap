"""Modbus 适配器集成测试 (T3/T4 验收)。

用本地 asyncio 假从站 (替代 ProtoForge 的最小测试替身, CI 无外部依赖)
覆盖: probe 四分类、plc_read 读写闭环、连接池复用、超时。
ProtoForge 实机联测属 M1 DoD 演示项, 不进 CI。
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
from plctap.protocols.base import adapter_for
from plctap.protocols.modbus.adapter import ModbusError, ModbusAdapter  # noqa: F401

adapter_for  # 确保导入顺序: 注册表登记发生在 import 副作用里


class FakeSlave:
    """最小 Modbus TCP 从站测试替身。

    mode:
    - normal:    正常回 FC03 (寄存器值 = 地址*3 + 7)
    - exception: 回 0x02 ILLEGAL_DATA_ADDRESS 异常帧
    - silent:    接受连接后不回话 (connected_but_no_reply 场景)
    - bad_frame: 回长度字段与实际不符的畸形帧
    """

    def __init__(self, mode: str = "normal") -> None:
        self.mode = mode
        self.server: asyncio.Server | None = None
        self.port = 0
        self._abort = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        """关监听 + 断开全部残余连接, 保证 handler 退出 (silent 模式靠本方法解困)。"""
        self._abort.set()
        for w in list(self._writers):
            w.close()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            while True:
                head = await reader.readexactly(7)
                length = struct.unpack_from(">H", head, 4)[0]
                rest = await reader.readexactly(length - 1)
                fc = rest[0]
                if self.mode == "silent":
                    # 等 abort 信号而不是死 sleep: 测试 teardown 时能干净退出
                    await self._abort.wait()
                    return
                if self.mode == "exception":
                    writer.write(head[:4] + struct.pack(">H", 3) + head[6:7] + bytes([fc | 0x80, 0x02]))
                    await writer.drain()
                    continue
                if self.mode == "bad_frame":
                    # 长度字段声称 100, 实际只发 2 字节 PDU
                    writer.write(head[:4] + struct.pack(">H", 100) + head[6:7] + bytes([fc, 0]))
                    await writer.drain()
                    continue
                if fc in (5, 6):
                    # 写请求: 响应为请求 PDU 的逐字节回显 (规范 6.5/6.6 节)
                    writer.write(head[:4] + struct.pack(">H", len(rest) + 1) + head[6:7] + rest)
                    await writer.drain()
                    continue
                _addr, qty = struct.unpack_from(">HH", rest, 1)
                data = b"".join(struct.pack(">H", (_addr + i) * 3 + 7) for i in range(qty))
                pdu = struct.pack(">BB", fc, len(data)) + data
                writer.write(head[:4] + struct.pack(">H", len(pdu) + 1) + head[6:7] + pdu)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            return
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()


def make_target(port: int) -> Target:
    return Target(protocol="modbus", host="127.0.0.1", port=port, unit=1)


def make_adapter(mode: str = "normal", timeout_ms: int = 1000):
    pool = ConnectionPool(idle_timeout_sec=60, max_per_target=2)
    config = PlctapConfig(default_timeout_ms=timeout_ms)
    adapter = ModbusAdapter(pool, config)
    return adapter, pool


@pytest.fixture
async def slave_factory():
    created: list[FakeSlave] = []

    async def _make(mode: str = "normal") -> FakeSlave:
        s = FakeSlave(mode)
        await s.start()
        created.append(s)
        return s

    yield _make
    for s in created:
        # silent 模式的 handler 靠 abort 事件退出, 这里统一收尾
        await s.stop()


async def test_probe_success(slave_factory):
    s = await slave_factory("normal")
    adapter, pool = make_adapter()
    r = await adapter.probe(make_target(s.port))
    assert r.reachable and r.failure_class is None and r.layer_hint == "application"
    await pool.close_all()


async def test_probe_exception_response(slave_factory):
    s = await slave_factory("exception")
    adapter, pool = make_adapter()
    r = await adapter.probe(make_target(s.port))
    assert not r.reachable
    assert r.failure_class == "exception_response"
    assert r.exception_code == 0x02
    assert r.layer_hint == "application"
    await pool.close_all()


async def test_probe_connected_but_no_reply(slave_factory):
    s = await slave_factory("silent")
    adapter, pool = make_adapter(timeout_ms=300)
    r = await adapter.probe(make_target(s.port))
    assert not r.reachable
    assert r.failure_class == "connected_but_no_reply"
    assert r.layer_hint == "protocol"
    await pool.close_all()


async def test_probe_connection_refused(monkeypatch):
    """refused 分类映射。

    注: 本机 (Windows + 防火墙) 对未监听端口一律丢 SYN -> 实际表现为
    timeout, 真实 socket 无法稳定复现 refused; 故 monkeypatch 验证
    ConnectionRefusedError -> connection_refused 的确定性映射。
    """
    import plctap.protocols.modbus.adapter as mod

    async def _refused(*args, **kwargs):
        raise ConnectionRefusedError()

    monkeypatch.setattr(mod.asyncio, "open_connection", _refused)
    adapter, pool = make_adapter()
    r = await adapter.probe(make_target(1))
    assert not r.reachable
    assert r.failure_class == "connection_refused"
    assert r.layer_hint == "connectivity"
    await pool.close_all()


async def test_probe_generic_oserror_is_refused(monkeypatch):
    import plctap.protocols.modbus.adapter as mod

    async def _unreachable(*args, **kwargs):
        raise OSError(65, "No route to host")

    monkeypatch.setattr(mod.asyncio, "open_connection", _unreachable)
    adapter, pool = make_adapter()
    r = await adapter.probe(make_target(1))
    assert r.failure_class == "connection_refused"
    await pool.close_all()


async def test_probe_closed_port_is_unreachable_connectivity():
    """真实关端口的平台无关断言: 不可达且定位在连接层。

    refused 还是 timeout 取决于 OS/防火墙对 SYN 的处理 (见
    test_probe_connection_refused 的注释), 这里不钉死分类。
    """
    s = FakeSlave("normal")
    await s.start()
    port = s.port
    await s.stop()
    adapter, pool = make_adapter()
    r = await adapter.probe(make_target(port))
    assert not r.reachable
    assert r.layer_hint == "connectivity"
    await pool.close_all()


async def test_read_registers(slave_factory):
    s = await slave_factory("normal")
    adapter, pool = make_adapter()
    r = await adapter.read(make_target(s.port), address=0, count=5)
    assert r.raw_registers == [(i * 3 + 7) for i in range(5)]
    assert r.interpreted == [(i * 3 + 7) for i in range(5)]
    # unit=1, fc3, addr=0, qty=5 (事务号由模块级计数器分配, 不钉死)
    assert r.request_frame.endswith("010300000005")
    assert r.elapsed_ms >= 0
    await pool.close_all()


async def test_read_fc4(slave_factory):
    s = await slave_factory("normal")
    adapter, pool = make_adapter()
    r = await adapter.read(make_target(s.port), address=10, count=2, function_code=4)
    assert r.raw_registers == [(10 + i) * 3 + 7 for i in range(2)]
    await pool.close_all()


async def test_read_float32(slave_factory):
    s = await slave_factory("normal")
    adapter, pool = make_adapter()
    r = await adapter.read(make_target(s.port), address=0, count=2, datatype="float32")
    # 假从站值 7, 10 -> 大端组合 0x0007 000A
    import struct as _s

    expected = _s.unpack(">f", bytes.fromhex("0007000A"))[0]
    assert r.interpreted == [pytest.approx(expected)]
    await pool.close_all()


async def test_read_exception_raises(slave_factory):
    s = await slave_factory("exception")
    adapter, pool = make_adapter()
    with pytest.raises(ModbusError, match="ILLEGAL_DATA_ADDRESS"):
        await adapter.read(make_target(s.port), address=0, count=1)
    await pool.close_all()


async def test_read_bad_frame_raises(slave_factory):
    """坏长度帧 (length=100 但数据不再发): 收包挂到超时, 包装成 ModbusError。"""
    s = await slave_factory("bad_frame")
    adapter, pool = make_adapter(timeout_ms=500)
    with pytest.raises(ModbusError, match="timeout"):
        await adapter.read(make_target(s.port), address=0, count=1)
    await pool.close_all()


async def test_read_timeout(slave_factory):
    s = await slave_factory("silent")
    adapter, pool = make_adapter(timeout_ms=300)
    with pytest.raises(ModbusError, match="timeout"):
        await adapter.read(make_target(s.port), address=0, count=1)
    await pool.close_all()


async def test_pool_reuses_connection(slave_factory):
    s = await slave_factory("normal")
    adapter, pool = make_adapter()
    target = make_target(s.port)
    await adapter.read(target, address=0, count=1)
    key = adapter.key_for(target)
    assert pool._idle.get(key), "首次读后连接应回池"
    conn1 = pool._idle[key][0]
    await adapter.read(target, address=0, count=1)
    assert pool._idle[key] and pool._idle[key][0] is conn1, "第二次读应复用同一连接"
    await pool.close_all()


async def test_pool_discards_on_protocol_error(slave_factory):
    """协议出错后连接被丢弃, 下次读新建连接仍能成功。"""
    s_bad = await slave_factory("bad_frame")
    adapter, pool = make_adapter(timeout_ms=500)
    target = make_target(s_bad.port)
    with pytest.raises(ModbusError):
        await adapter.read(target, address=0, count=1)
    assert not pool._idle.get(adapter.key_for(target))
    s_good = await slave_factory("normal")
    target2 = make_target(s_good.port)
    r = await adapter.read(target2, address=0, count=1)
    assert r.raw_registers == [7]
    await pool.close_all()


async def test_register_table_exposes_modbus():
    from plctap.protocols.base import known_protocols

    assert "modbus" in known_protocols()

async def test_write_register_roundtrip(slave_factory):
    """fc06 写保持寄存器: 响应为请求回显, 返回含请求帧。"""
    s = await slave_factory("normal")
    adapter, _ = make_adapter()
    out = await adapter.write(make_target(s.port), address=42, values=[0xABCD])
    assert out["request_frame"] == out["response_frame"]
    assert out["request_frame"].endswith("06" + "002a" + "abcd")


async def test_write_coil_wire_value(slave_factory):
    """fc05 线圈应用值 1 -> 线上 0xFF00 (规范 6.5 节)。"""
    s = await slave_factory("normal")
    adapter, _ = make_adapter()
    out = await adapter.write(make_target(s.port), address=7, values=[1], point_type="coil")
    assert "0500" in out["request_frame"] and "07ff00" in out["request_frame"]


async def test_write_on_frame_called_before_send(slave_factory):
    """on_frame 在发送前收到完整请求帧 (审计契约)。"""
    s = await slave_factory("normal")
    adapter, _ = make_adapter()
    seen: list[str] = []
    await adapter.write(make_target(s.port), address=1, values=[5], on_frame=seen.append)
    assert len(seen) == 1 and len(seen[0]) == 24  # 12 字节帧 = 24 hex 字符


async def test_write_exception_raises(slave_factory):
    s = await slave_factory("exception")
    adapter, _ = make_adapter()
    with pytest.raises(ModbusError, match="ILLEGAL"):
        await adapter.write(make_target(s.port), address=0, values=[1])


async def test_write_invalid_point_type():
    adapter, _ = make_adapter()
    with pytest.raises(ValueError, match="point_type"):
        await adapter.write(make_target(1), address=0, values=[1], point_type="bank")
