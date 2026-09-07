"""EtherNet/IP (CIP) 与 pycomm3 (权威 Rockwell 客户端库) 的交叉验证 e2e。

pycomm3 的 CIPDriver 从 path 字符串解析 ip:port (port kwarg 无效), 本测试
用 f"127.0.0.1:{port}"。generic_message 的 data_type 语义是"裸应答解码"
(不含 Read Tag 应答的类型码前缀), 因此用 UINT 解码并断言首字 = 我们的
类型码 0x00C4 (DINT) —— 官方实现逐字节解析了 plctap 的应答帧。

CI 无 pycomm3 时自动跳过 (e2e extra 含 pycomm3)。
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("plctap")
pycomm3 = pytest.importorskip("pycomm3")
from pycomm3.cip.data_types import UINT  # noqa: E402

from plctap.config import PlctapConfig  # noqa: E402
from plctap.listener import ListenerRegistry  # noqa: E402


def test_pycomm3_client_parses_plctap_listener_frames():
    """官方 pycomm3 客户端: RegisterSession + Read Tag 全流程对 plctap 监听器。"""

    async def run():
        reg = ListenerRegistry()
        info = await reg.start("enip", "127.0.0.1", 0, "respond_normal", idle_timeout_sec=90)
        port = info["port"]

        def pycomm3_side():
            drv = pycomm3.CIPDriver(f"127.0.0.1:{port}", socket_timeout=5)
            assert drv.open() is True  # RegisterSession: 我们的应答被官方实现接受
            from plctap.protocols.enip import codec as ec

            req_data = ec.build_tag_path("alpha[0]") + UINT.encode(1)
            tag = drv.generic_message(
                service=0x4C, class_code=0x02, instance=1,
                request_data=req_data, name="alpha0", connected=False,
                data_type=UINT, unconnected_send=False, route_path=False,
            )
            drv.close()
            return tag

        try:
            # pycomm3 是阻塞式同步客户端: 丢进线程, 与监听器同循环
            tag = await asyncio.to_thread(pycomm3_side)
        finally:
            await reg.stop(port)
        return tag

    tag = asyncio.run(run())
    # 罐头读应答 CIP = [CC,00,00,00][C4 00][2A 00 00 00]:
    # pycomm3 裸解码 UINT 的首字 = 类型码 0x00C4 = 196 —— 官方实现逐字节
    # 解析了 plctap 的应答 (帧结构/项类型/CIP 应答头全部正确)
    assert tag.error is None
    assert tag.value == 0x00C4


def test_plctap_adapter_reads_own_fixture():
    """plctap 适配器读写闭环 (fixture 罐头: alpha=DINT 42 起, beta=REAL 0.25 起)。"""
    pytest.importorskip("asyncio")

    async def run():
        from plctap.config import PlctapConfig
        from plctap.conn.manager import ConnectionPool
        from plctap.models import Target
        from tests.test_adapter_enip import FakeEnipServer
        from plctap.protocols.enip.adapter import EnipAdapter

        s = FakeEnipServer()
        host, port = await s.start()
        try:
            pool = ConnectionPool(PlctapConfig())
            ad = EnipAdapter(pool, PlctapConfig())
            t = Target(protocol="enip", host=host, port=port, unit=1)
            r = await ad.read(t, "alpha[0]", 3, datatype="dint")
            await pool.close_all()
            await s.stop()
            return r.interpreted
        except BaseException:
            await s.stop()
            raise

    assert asyncio.run(run()) == [42, 43, 44]
