"""跨厂商实机交叉验证 (e2e, 全真实 socket)。

与 tests/ 里的进程内 fake server 不同, 本目录用**第三方权威实现**做实机
交叉验证 —— "plctap 帧与权威实现互通" 的可持续保障, CI 随每次改动回归:

- pymodbus    从站 + 客户端  <-> plctap 适配器 (Modbus TCP 读写闭环)
- snap7       服务器 + 客户端 <-> plctap 适配器 (S7 读交叉比对)
- pymcprotocol 客户端         <-> plctap 钓鱼监听 (MELSEC 全部 4 种帧格式)
- pypi fins   客户端          <-> plctap 钓鱼监听 (FINS/TCP 读写闭环)

需要 `uv sync --group e2e`; 缺库整文件跳过。
"""

from __future__ import annotations

import asyncio
import socket
import struct
import threading
import time

import pytest

pytest.importorskip("pymodbus")
pytest.importorskip("snap7")
pytest.importorskip("pymcprotocol")
pytest.importorskip("fins")

pytestmark = pytest.mark.e2e

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.listener import ListenerRegistry
from plctap.models import Target
from plctap.protocols.base import adapter_for
import plctap.protocols.modbus.adapter  # noqa: F401
import plctap.protocols.s7.adapter  # noqa: F401


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


# ---------------------------------------------------------------- Modbus (pymodbus)

# 从站数据布局 (两代 API 共用): 外部地址 -> 值
#   0..3   -> [100, 200, 300, 0x41F0]  (读验证)
#   8..9   -> [1234, 5678]             (写验证)
_MB_HR_VALUES = [100, 200, 300, 0x41F0, 0, 0, 42, 7, 0, 0] + [0] * 6


def _pymodbus_context():
    """按 pymodbus 版本构建从站。

    3.15 弃用 ModbusSlaveContext/ModbusServerContext (legacy 包装会丢失
    块起始地址), 用新 SimDevice/SimData API —— 外部地址 0 直接对应
    SimData 偏移 0 (无老版本的 address+1 偏移)。
    """
    from pymodbus.simulator.simdevice import SimDevice
    from pymodbus.simulator.simdata import SimData, DataType

    hr = SimData(address=0, count=20, values=_MB_HR_VALUES, datatype=DataType.REGISTERS)
    co = SimData(address=0, count=16, datatype=DataType.BITS)
    di = SimData(address=0, count=16, datatype=DataType.BITS)
    ir = SimData(address=0, count=16, datatype=DataType.REGISTERS)
    return SimDevice(id=1, simdata=([co], [di], [hr], [ir]))


@pytest.fixture(scope="module")
def modbus_port():
    from pymodbus.server import StartTcpServer

    port = _free_port()
    thread = threading.Thread(
        target=StartTcpServer,
        kwargs={"context": _pymodbus_context(),
                "address": ("127.0.0.1", port)},
        daemon=True,
    )
    thread.start()
    _wait_port(port)
    return port


def _modbus_client_kwargs(**kw):
    """3.15 起 slave= 更名 device_id=。"""
    import pymodbus

    key = "device_id" if int(pymodbus.__version__.split(".")[1]) >= 15 else "slave"
    return {key: 1, **kw}


def test_modbus_read_and_write_cross_check_with_pymodbus(modbus_port):
    """plctap 读写闭环: 读数与从站一致, 写入后由 pymodbus 客户端交叉读回。"""
    from pymodbus.client import ModbusTcpClient

    async def run():
        adapter = adapter_for("modbus")(ConnectionPool(PlctapConfig()), PlctapConfig())
        target = Target(protocol="modbus", host="127.0.0.1", port=modbus_port, unit=1)
        r = await adapter.read(target, 0, 4, datatype="uint16", function_code=3)
        w = await adapter.write(target, 8, [1234, 5678], point_type="register")
        await adapter.pool.close_all()
        return r.raw_registers, w

    raw, _w = asyncio.run(run())

    assert raw == [100, 200, 300, 0x41F0]

    client = ModbusTcpClient("127.0.0.1", port=modbus_port)
    assert client.connect()
    rr = client.read_holding_registers(8, count=2, **_modbus_client_kwargs())
    assert not rr.isError() and rr.registers == [1234, 5678]
    client.close()


# ---------------------------------------------------------------- S7 (snap7)


@pytest.fixture(scope="module")
def s7_port():
    import snap7

    srv = snap7.Server(log=False)
    db1 = bytearray(100)
    db1[0:8] = bytes([0x12, 0x34, 0x56, 0x78, 0x41, 0xF0, 0x00, 0x00])
    srv.register_area(snap7.type.SrvArea.DB, 1, db1)
    mk = bytearray(64)
    mk[0:8] = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x42, 0x48, 0x00, 0x00])
    srv.register_area(snap7.type.SrvArea.MK, 0, mk)
    port = _free_port()
    srv.start(tcp_port=port)
    _wait_port(port)
    yield port
    srv.stop()
    srv.destroy()


def test_s7_read_cross_check_with_snap7_client(s7_port):
    """plctap 与 snap7 官方客户端对同一 DB/M 区读数逐值一致。"""
    import asyncio

    from snap7.client import Client
    from snap7.type import Areas

    adapter = adapter_for("s7")(ConnectionPool(PlctapConfig()), PlctapConfig())
    target = Target(protocol="s7", host="127.0.0.1", port=s7_port, unit=1)

    async def run():
        db = await adapter.read(target, 0, 8, datatype="uint16",
                                area="DB", db_number=1)
        mk = await adapter.read(target, 0, 8, datatype="uint16", area="M")
        return db.raw_registers, mk.raw_registers

    db_words, mk_words = asyncio.run(run())

    client = Client()
    client.connect("127.0.0.1", 0, 1, tcp_port=s7_port)
    db_ref = list(struct.unpack(">4H", bytes(client.db_read(1, 0, 8))))
    mk_ref = list(struct.unpack(">4H", bytes(client.read_area(Areas.MK, 0, 0, 8))))
    client.disconnect()
    client.destroy()

    assert db_words == db_ref == [0x1234, 0x5678, 0x41F0, 0x0000]
    assert mk_words == mk_ref == [0xAABB, 0xCCDD, 0x4248, 0x0000]


# ---------------------------------------------------------------- 监听器交叉验证


async def test_melsec_listener_vs_pymcprotocol_all_formats():
    """pymcprotocol 权威客户端打入 plctap 监听器 (4 种帧格式), 解出全零响应。

    客户端是同步 socket 实现, 必须放线程执行 —— 否则阻塞事件循环,
    监听器无法应答, 自锁超时。
    """
    pymcprotocol = pytest.importorskip("pymcprotocol")

    def client_flow(port: int) -> None:
        for name, cls, ascii_mode in (
            ("3e_binary", pymcprotocol.Type3E, None),
            ("3e_ascii", pymcprotocol.Type3E, "ascii"),
            ("4e_binary", pymcprotocol.Type4E, None),
            ("4e_ascii", pymcprotocol.Type4E, "ascii"),
        ):
            p = cls()
            if ascii_mode:
                p._set_commtype(ascii_mode)
            p.connect("127.0.0.1", port)
            vals = p.batchread_wordunits("D100", 5)
            assert vals == [0] * 5, f"{name}: {vals}"
            p.close()

    registry = ListenerRegistry()
    port = (await registry.start("melsec", "127.0.0.1", 0, "respond_normal",
                                 idle_timeout_sec=10))["port"]
    try:
        await asyncio.to_thread(client_flow, port)
    finally:
        await registry.stop(port)


async def test_fins_listener_vs_pypifins_client():
    """pypi fins 权威客户端打入 plctap 监听器: 握手 + DM 读全零。"""
    from fins.tcp import TCPFinsConnection

    def client_flow(port: int) -> None:
        conn = TCPFinsConnection()
        conn.connect("127.0.0.1", port, bind_port=0)
        conn.node_address_data_send()
        words = conn.read("d", 100, data_type="w", number_of_values=3)
        # 该版本 fins 包 'w' 类型返回原始 2 字节字
        assert [int.from_bytes(w, "big") for w in words] == [0, 0, 0]
        conn.fins_socket.close()

    registry = ListenerRegistry()
    port = (await registry.start("fins", "127.0.0.1", 0, "respond_normal",
                                 idle_timeout_sec=10))["port"]
    try:
        await asyncio.to_thread(client_flow, port)
    finally:
        await registry.stop(port)
