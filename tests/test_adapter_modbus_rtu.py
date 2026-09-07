"""Modbus RTU over TCP 适配器测试: 进程内 fake 网关 (与 test_adapter_modbus.py 同思路)。

RTU over TCP 无长度字段, fake 服务端按 FC 定长收请求 (与真网关一致),
响应覆盖 正常/异常/坏CRC/错地址/分段发送 各路径。
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator

import pytest

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
from plctap.protocols.modbus.adapter import ModbusError, ModbusRtuOverTcpAdapter
from plctap.protocols.modbus import codec as mb


class FakeRtuGateway:
    """RTU over TCP 假网关: 按从站地址+FC 定长收请求, 回 RTU 帧。

    mode: normal / bad_crc(响应 CRC 错) / wrong_addr(响应从站地址错)
    / exception(对读请求回 fc|0x80 异常) / silent(收请求不回话)。split=True 时响应分两个 TCP 段发送 (切帧鲁棒性)。
    """

    def __init__(self, mode: str = "normal", split: bool = False) -> None:
        self.mode = mode
        self.split = split
        self.requests: list[bytes] = []
        self._server: asyncio.Server | None = None
        self._abort = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        return "127.0.0.1", self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._abort.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for w in list(self._writers):
            w.close()

    @staticmethod
    def _rtu(addr: int, pdu: bytes) -> bytes:
        body = bytes([addr]) + pdu
        return body + struct.pack("<H", mb.crc16(body))

    async def _recv_request(self, reader: asyncio.StreamReader) -> bytes | None:
        addr = await asyncio.wait_for(reader.readexactly(1), 0.5)
        fc = (await asyncio.wait_for(reader.readexactly(1), 0.5))[0]
        if fc == mb.WRITE_MULTIPLE_REGISTERS:
            head = await asyncio.wait_for(reader.readexactly(5), 1.0)  # addr2+qty2+bc
            bc = head[4]
            data = await asyncio.wait_for(reader.readexactly(bc + 2), 1.0)  # data+crc
            return addr + bytes([fc]) + head + data
        # fc01-06 请求恒 8 字节
        rest = await asyncio.wait_for(reader.readexactly(6), 1.0)
        return addr + bytes([fc]) + rest

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            while not self._abort.is_set():
                try:
                    req = await self._recv_request(reader)
                except (TimeoutError, asyncio.IncompleteReadError):
                    continue  # EOF/空闲: 回到循环等新请求 (EOF return 会饿死事件循环)
                self.requests.append(req)
                if self.mode == "silent":
                    await self._abort.wait()
                    continue
                addr = req[0]
                fc = req[1]
                if fc & mb.EXCEPTION_FLAG:
                    continue
                if self.mode == "bad_crc":
                    resp = self._rtu(addr, bytes([fc, 2, 0, 0]) + b"\x00")  # 随意帧
                    resp = resp[:-2] + b"\x00\x00"
                elif self.mode == "wrong_addr":
                    resp = self._rtu((addr + 1) & 0xFF, bytes([fc, 2, 0, 0]))
                elif self.mode == "exception":
                    resp = self._rtu(addr, bytes([fc | mb.EXCEPTION_FLAG, 0x01]))
                else:
                    resp = self._respond(addr, fc, req)
                if self.split:
                    writer.write(resp[:3])
                    await writer.drain()
                    await asyncio.sleep(0.02)
                    writer.write(resp[3:])
                else:
                    writer.write(resp)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            if not writer.is_closing():
                writer.close()

    @staticmethod
    def _respond(addr: int, fc: int, req: bytes) -> bytes:
        if fc in (mb.READ_HOLDING_REGISTERS, mb.READ_INPUT_REGISTERS):
            (qty,) = struct.unpack_from(">H", req, 4)
            return FakeRtuGateway._rtu(
                addr, bytes([fc, qty * 2]) + b"".join(struct.pack(">H", 0x2000 + i) for i in range(qty))
            )
        if fc in (mb.WRITE_SINGLE_COIL, mb.WRITE_SINGLE_REGISTER):
            return req  # 写单点回显
        if fc == mb.WRITE_MULTIPLE_REGISTERS:
            return FakeRtuGateway._rtu(addr, bytes([fc]) + req[2:6])  # 回显 fc+addr2+qty2
        return FakeRtuGateway._rtu(addr, bytes([0x84, 0x01]))  # 其它 fc 回异常


@pytest.fixture
async def rtu_gateway() -> AsyncIterator[FakeRtuGateway]:
    server = FakeRtuGateway()
    server.addr = await server.start()
    yield server
    await server.stop()


def make_adapter(host: str, port: int):
    pool = ConnectionPool(idle_timeout_sec=5.0)
    config = PlctapConfig(default_timeout_ms=1000)
    target = Target(protocol="modbus_rtu", host=host, port=port, unit=5)
    return ModbusRtuOverTcpAdapter(pool, config), pool, target


async def test_rtu_probe_ok(rtu_gateway):
    adapter, pool, target = make_adapter(*rtu_gateway.addr)
    try:
        r = await adapter.probe(target)
        assert r.reachable and r.layer_hint == "application"
    finally:
        await pool.close_all()


async def test_rtu_read_and_frame_shape(rtu_gateway):
    adapter, pool, target = make_adapter(*rtu_gateway.addr)
    try:
        r = await adapter.read(target, address=0, count=3)
        assert r.raw_registers == [0x2000, 0x2001, 0x2002]
        # RTU 帧壳: 首字节=从站地址 5, 无 MBAP (无事务号/协议号), 尾部 CRC
        req = bytes.fromhex(r.request_frame)
        assert req[0] == 5 and req[1] == 3 and len(req) == 8
        assert struct.unpack_from("<H", req, 6)[0] == mb.crc16(req[:6])
    finally:
        await pool.close_all()


async def test_rtu_read_split_response(rtu_gateway):
    """响应分两个 TCP 段到达: 按 FC 定长切帧必须正确重组。"""
    server = FakeRtuGateway(split=True)
    host, port = await server.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.read(target, address=0, count=2)
        assert r.raw_registers == [0x2000, 0x2001]
    finally:
        await pool.close_all()
        await server.stop()


async def test_rtu_write_fc16_echo(rtu_gateway):
    adapter, pool, target = make_adapter(*rtu_gateway.addr)
    try:
        r = await adapter.write(target, address=10, values=[100, 200])
        resp = bytes.fromhex(r["response_frame"])
        assert resp[0] == 5 and resp[1] == mb.WRITE_MULTIPLE_REGISTERS
        assert struct.unpack_from(">H", resp, 2)[0] == 10  # 回显起始地址
        # 请求已被网关收到且 PDU 语义与 TCP 一致
        sent = rtu_gateway.requests[-1]
        assert sent[1] == mb.WRITE_MULTIPLE_REGISTERS
    finally:
        await pool.close_all()


async def test_rtu_read_exception_raises():
    """从站回异常响应: 报错带异常码名 (RTU 轨道与 TCP 轨道同一 KB)。"""
    server = FakeRtuGateway(mode="exception")
    host, port = await server.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        with pytest.raises(ModbusError, match="ILLEGAL_FUNCTION"):
            await adapter.read(target, address=0, count=2)
    finally:
        await pool.close_all()
        await server.stop()


async def test_rtu_bad_crc_is_no_reply():
    server = FakeRtuGateway(mode="bad_crc")
    host, port = await server.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        r = await adapter.probe(target)
        assert not r.reachable
        assert r.failure_class == "connected_but_no_reply"
    finally:
        await pool.close_all()
        await server.stop()


async def test_rtu_wrong_addr_cross_check():
    """响应从站地址与请求不符 (网关错路由/串包): 交叉校验拦截。"""
    server = FakeRtuGateway(mode="wrong_addr")
    host, port = await server.start()
    adapter, pool, target = make_adapter(host, port)
    try:
        with pytest.raises(ModbusError, match="malformed"):
            await adapter.read(target, address=0, count=1)
    finally:
        await pool.close_all()
        await server.stop()


async def test_rtu_send_raw_accumulates(rtu_gateway):
    adapter, pool, target = make_adapter(*rtu_gateway.addr)
    try:
        req = mb.rtu_request_from_tcp(
            mb.build_read_request(0, 5, mb.READ_HOLDING_REGISTERS, 0, 2)
        )
        ex = await adapter.send_raw(target, req.hex())
        assert ex.received_frame.startswith("05" + "03")  # addr + fc
    finally:
        await pool.close_all()
