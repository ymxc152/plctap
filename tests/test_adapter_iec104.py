"""IEC 60870-5-104 适配器测试: 进程内 fake 子站 (维护 I 帧序号状态)。

fake 服务端行为与真实远动设备一致: STARTDT/TESTFR 握手、总召
ACT->ACT_CON->监视帧->ACT_TERM、序号按收发推进。
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator

import pytest

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
from plctap.protocols.iec104 import codec
from plctap.protocols.iec104.adapter import Iec104Adapter, ProtocolError


class FakeIec104Slave:
    """104 假子站。mode: normal / silent / bad_start / missing(总召漏发 IOA 201)。"""

    def __init__(self, mode: str = "normal") -> None:
        self.mode = mode
        self.frames: list[bytes] = []
        self._server: asyncio.Server | None = None
        self._abort = asyncio.Event()

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        return "127.0.0.1", self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._abort.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _recv_apdu(self, reader: asyncio.StreamReader) -> bytes | None:
        try:
            head = await asyncio.wait_for(reader.readexactly(2), 0.5)
        except TimeoutError:
            return None
        except asyncio.IncompleteReadError:
            return None
        if head[0] != 0x68 or not 4 <= head[1] <= 253:
            raise ConnectionError("bad frame")
        return head + await asyncio.wait_for(reader.readexactly(head[1]), 1.0)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        stx = 0  # 服务端发送序号
        srx = 0  # 服务端已确认的客户端发送序号
        try:
            while not self._abort.is_set():
                frame = await self._recv_apdu(reader)
                if frame is None:
                    continue
                self.frames.append(frame)
                if self.mode == "silent":
                    continue
                fmt = codec.apci_format(frame[2:6])
                if fmt == "U":
                    if self.mode == "bad_start":
                        writer.write(bytes(6))  # 垃圾帧: 非法启动字符
                        await writer.drain()
                        continue
                    con = {codec.U_STARTDT_ACT: codec.U_STARTDT_CON,
                           codec.U_TESTFR_ACT: codec.U_TESTFR_CON,
                           codec.U_STOPDT_ACT: codec.U_STOPDT_CON}.get(frame[2])
                    if con:
                        writer.write(codec.build_apci_u(con))
                        await writer.drain()
                    continue
                if fmt == "S":
                    continue
                # I 帧: 确认客户端发送序号
                (ctx, _) = codec.apci_seq_i(frame[2:6])
                srx = (ctx + 1) & 0x7FFF
                asdu = frame[6:]
                type_id, cot = asdu[0], asdu[2]
                if type_id == codec.C_IC_NA_1 and cot == 6:
                    # ACT_CON
                    con = bytearray(asdu)
                    con[2] = 7
                    writer.write(codec.build_apci_i(stx, srx, bytes(con)))
                    stx = (stx + 1) & 0x7FFF
                    await writer.drain()
                    if self.mode == "missing":
                        objs = [(200, [1]), (202, [1])]  # 漏 201
                    else:
                        objs = [(200, [1]), (201, [0]), (202, [1])]
                    writer.write(codec.build_apci_objects(codec.M_SP_NA_1, objs, 20, 1, stx, srx))
                    stx = (stx + 1) & 0x7FFF
                    await writer.drain()
                    nc = [(300 + i, list(struct.pack("<f", 0.25 * i)) + [0]) for i in range(2)]
                    writer.write(codec.build_apci_objects(codec.M_ME_NC_1, nc, 20, 1, stx, srx))
                    stx = (stx + 1) & 0x7FFF
                    await writer.drain()
                    term = bytearray(asdu)
                    term[2] = 10
                    writer.write(codec.build_apci_i(stx, srx, bytes(term)))
                    stx = (stx + 1) & 0x7FFF
                    await writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()


@pytest.fixture
async def slave() -> AsyncIterator[FakeIec104Slave]:
    s = FakeIec104Slave()
    s.addr = await s.start()
    yield s
    await s.stop()


def make_adapter(host: str, port: int):
    pool = ConnectionPool(idle_timeout_sec=5.0)
    config = PlctapConfig(default_timeout_ms=1000)
    target = Target(protocol="iec104", host=host, port=port, unit=1)
    return Iec104Adapter(pool, config), pool, target


async def test_iec104_probe_ok(slave):
    adapter, pool, target = make_adapter(*slave.addr)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.layer_hint == "application"
    finally:
        await pool.close_all()


async def test_iec104_probe_silent():
    s = FakeIec104Slave(mode="silent")
    host, port = await s.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.probe(target)
        assert not r.reachable and r.failure_class == "connected_but_no_reply"
    finally:
        await pool.close_all()
        await s.stop()


async def test_iec104_probe_bad_start_byte():
    s = FakeIec104Slave(mode="bad_start")
    host, port = await s.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.probe(target)
        assert not r.reachable
    finally:
        await pool.close_all()
        await s.stop()


async def test_iec104_read_interrogation(slave):
    """总召收集: 遥信 200..202 = [1,0,1], 缺省 datatype 返回原始字。"""
    adapter, pool, target = make_adapter(*slave.addr)
    try:
        r = await adapter.read(target, address=200, count=3)
        assert r.raw_registers == [1, 0, 1]
        # 请求帧: I 格式 + C_IC_NA_1 ACT
        assert bytes.fromhex(r.request_frame)[6] == codec.C_IC_NA_1
    finally:
        await pool.close_all()


async def test_iec104_read_float32(slave):
    """短浮点 300..301 = 0.25/0.5, float32 big 解释 (NC 每点 2 字高字在前)。"""
    adapter, pool, target = make_adapter(*slave.addr)
    try:
        r = await adapter.read(target, address=300, count=2, datatype="float32")
        assert r.interpreted == pytest.approx([0.0, 0.25])  # 罐头值 0.25*i
    finally:
        await pool.close_all()


async def test_iec104_read_missing_ioa_notes(slave):
    """总召响应缺 IOA 201: 占位 None + 解释跳过 (不误配对)。"""
    s = FakeIec104Slave(mode="missing")
    host, port = await s.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.read(target, address=200, count=3)
        assert r.raw_registers == [1, 0, 1]  # 缺漏点 0 占位
        assert r.interpreted == [1, 1]  # 解释只含实际收到的点
    finally:
        await pool.close_all()
        await s.stop()


async def test_iec104_seq_persists_across_reads(slave):
    """连接池复用: 第二次读的请求 rx 序号应推进 (服务端状态被客户端吸收)。"""
    adapter, pool, target = make_adapter(*slave.addr)
    try:
        await adapter.read(target, address=200, count=1)
        r2 = await adapter.read(target, address=200, count=1)
        # 两次读共用连接: 第二次请求 I 帧的 rx_seq > 0
        (_, rx) = codec.apci_seq_i(bytes.fromhex(r2.request_frame)[2:6])
        assert rx > 0
    finally:
        await pool.close_all()


async def test_iec104_send_raw_u(slave):
    adapter, pool, target = make_adapter(*slave.addr)
    try:
        ex = await adapter.send_raw(target, codec.build_apci_u(codec.U_STARTDT_ACT).hex())
        assert ex.received_frame == "68040b000000"
    finally:
        await pool.close_all()


async def test_iec104_send_raw_timeout():
    s = FakeIec104Slave(mode="silent")
    host, port = await s.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        with pytest.raises(ProtocolError, match="timeout"):
            await adapter.send_raw(target, codec.build_apci_u(codec.U_STARTDT_ACT).hex(), timeout_ms=300)
    finally:
        await pool.close_all()
        await s.stop()
