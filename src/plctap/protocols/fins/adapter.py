"""Omron FINS/TCP 适配器 (M2)。

会话细节全部封装在本模块内 (D1): 节点连接握手 (TCP cmd 0x00/0x01) 在
每条连接首次使用时自动完成, 状态存 conn.metadata, 随连接复用/销毁。
工具层只见 host/port/area/address, 从不感知节点号握手。

节点号决策: 客户端节点号固定 1。FINS 网络内节点号需唯一, 单客户端
(本工具的典型场景) 固定值安全; 多客户端并存时需在配置层开放 —— 留到
出现真实冲突再引入, 避免过早配置化。
"""

from __future__ import annotations

import asyncio
import itertools
import struct
import time
from typing import Callable

from plctap.models import (
    ByteOrder,
    ProbeResult,
    RawExchange,
    ReadResult,
    Target,
)
from plctap.protocols.base import ProtocolAdapter, ProtocolError, recv_exact, register_adapter
from plctap.protocols.fins import codec
from plctap.protocols.fins import meta as _meta

FINS_CLIENT_NODE = 1


@register_adapter
class FinsAdapter(ProtocolAdapter):
    name = "fins"
    meta = _meta.META

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sids = itertools.cycle(range(1, 256))

    # ------------------------------------------------------------ 收帧

    async def _recv_tcp_frame(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> bytes:
        """按 TCP 头长度字段收一帧 (16B 头 + length-12 载荷)。"""
        head = await recv_exact(reader, codec.TCP_HEADER_LEN, timeout)
        if head[:4] != codec.TCP_MAGIC:
            raise ProtocolError(f"bad FINS/TCP magic {head[:4]!r}, stream out of sync")
        (length,) = struct.unpack_from(">I", head, 4)
        # length = command(4) + error(4) + payload; 头里已含 command+error
        if not 8 <= length <= 0x4000:
            raise ProtocolError(f"implausible FINS/TCP length {length}, aborting read")
        payload = await recv_exact(reader, length - 8, timeout)
        return head + payload

    async def _ensure_handshake(
        self, conn, target: Target, timeout: float
    ) -> None:
        """节点连接握手: 每连接一次, 结果记入 conn.metadata。"""
        if conn.metadata.get("fins_handshaked"):
            return
        request = codec.build_handshake_request(FINS_CLIENT_NODE)
        conn.writer.write(request)
        await asyncio.wait_for(conn.writer.drain(), timeout)
        resp = await self._recv_tcp_frame(conn.reader, timeout)
        info = codec.parse_handshake_response(resp)
        if info["error"] != 0:
            raise ProtocolError(f"node handshake rejected, tcp error {info['error']:#010x}")
        conn.metadata["fins_handshaked"] = True
        conn.metadata["server_node"] = info["server_node"]

    async def _exchange(
        self,
        target: Target,
        build_request: "Callable[[int], bytes]",
        timeout: float,
    ) -> tuple[bytes, bytes]:
        """锁内: 取连接 -> (按需)握手 -> 构建 -> 发送 -> 收帧 -> 归还。

        build_request 收到握手确认的 server_node (未握手到则 0), 用于把
        FINS 请求的 DA1 定向到实际应答节点 —— 否则多节点网络里响应的
        SA1 与请求 DA1 错位, 交叉校验会误报 (node mismatch)。
        握手状态挂在 conn.metadata 上, 通用 locked_exchange 的 recv 回调
        拿不到 conn, 因此展开为定制版并保留同样的锁/丢弃/归还语义。
        """
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            conn = await self.pool.acquire(key, timeout)
            try:
                await self._ensure_handshake(conn, target, timeout)
                server_node = conn.metadata.get("server_node")
                server_node = server_node if isinstance(server_node, int) else 0
                request = build_request(server_node)
                conn.writer.write(request)
                await asyncio.wait_for(conn.writer.drain(), timeout)
                resp = await self._recv_tcp_frame(conn.reader, timeout)
            except ProtocolError:
                self.pool.discard(conn)
                raise
            except TimeoutError:
                self.pool.discard(conn)
                raise ProtocolError(
                    f"timeout waiting for response from {key.target}"
                ) from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)
                return request, resp

    # ------------------------------------------------------------ probe

    async def probe(self, target: Target) -> ProbeResult:
        """probe 刻意不走连接池 (与 Modbus 同理): 一次性连接即用即关。"""
        timeout = self.timeout(None)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout
            )
        except ConnectionRefusedError:
            return ProbeResult(reachable=False, failure_class="connection_refused", layer_hint="connectivity")
        except TimeoutError:
            return ProbeResult(reachable=False, failure_class="timeout", layer_hint="connectivity")
        except OSError:
            return ProbeResult(reachable=False, failure_class="connection_refused", layer_hint="connectivity")
        try:
            request = codec.build_read_request(
                next(self._sids), FINS_CLIENT_NODE, codec.AREA_CODES["DM"], 0, 1
            )
            # 一次性连接上手动做握手 (不经 conn.metadata)
            writer.write(codec.build_handshake_request(FINS_CLIENT_NODE))
            await asyncio.wait_for(writer.drain(), timeout)
            hs_resp = await self._recv_tcp_frame(reader, timeout)
            codec.parse_handshake_response(hs_resp)
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout)
            resp = await self._recv_tcp_frame(reader, timeout)
        except (ProtocolError, TimeoutError, asyncio.IncompleteReadError, OSError, ConnectionError):
            # TCP 已建立但没完成一次完整协议交互: 应用层没回话
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")
        finally:
            writer.close()
        parsed = codec.parse_response(resp)
        end_field = next((f for f in parsed.fields if f.name == "end_code"), None)
        if end_field is None:
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")
        end_code = end_field.value
        if isinstance(end_code, int) and end_code != 0:
            return ProbeResult(
                reachable=True,
                failure_class="exception_response",
                exception_code=end_code,
                layer_hint="application",
            )
        return ProbeResult(reachable=True, layer_hint="application")

    # ------------------------------------------------------------ read

    async def read(
        self,
        target: Target,
        address: int,
        count: int,
        datatype: str | None = None,
        byteorder: ByteOrder = "big",
        timeout_ms: int | None = None,
        area: str = "DM",
    ) -> ReadResult:
        """读存储区 (0101, 字单位)。area 取 CIO/W/H/A/DM/EM, 默认 DM。"""
        timeout = self.timeout(timeout_ms)
        area_code = codec.AREA_CODES.get(area)
        if area_code is None:
            raise ValueError(f"unknown area {area!r}; known: {sorted(codec.AREA_CODES)}")
        sid = next(self._sids)

        def _build(server_node: int) -> bytes:
            # DA1 定向到握手确认的 server_node (默认 0 = 本网直连)
            return codec.build_read_request(
                sid, FINS_CLIENT_NODE, area_code, address, count, dest_node=server_node
            )

        started = time.perf_counter()
        request, resp = await self._exchange(target, _build, timeout)
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        parsed = codec.parse_response(resp, request=request)
        end_field = next((f for f in parsed.fields if f.name == "end_code"), None)
        if end_field is None:
            raise FinsError("malformed response: no end code found; " + "; ".join(parsed.errors))
        end_code = end_field.value
        if isinstance(end_code, int) and end_code != 0:
            raise FinsError(
                f"device returned end code {codec.end_code_name(end_code)} ({end_code:#06x})"
                f" for area {area} address={address} count={count}"
            )
        if not parsed.valid:
            raise FinsError("malformed response: " + "; ".join(parsed.errors))
        values_field = next(f for f in parsed.fields if f.name == "word_values")
        raw = list(values_field.value)  # type: ignore[arg-type]
        if len(raw) < count:
            raise FinsError(f"device returned {len(raw)} words, requested {count}")
        interpreted = codec.interpret_registers(raw, datatype, byteorder)
        return ReadResult(
            target=target,
            address=address,
            request_frame=request.hex(),
            raw_registers=raw,
            interpreted=interpreted,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------ send_raw

    async def send_raw(
        self, target: Target, frame_hex: str, timeout_ms: int | None = None
    ) -> RawExchange:
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            conn = await self.pool.acquire(key, timeout)
            try:
                await self._ensure_handshake(conn, target, timeout)
                conn.writer.write(frame)
                await asyncio.wait_for(conn.writer.drain(), timeout)
                resp = await self._recv_tcp_frame(conn.reader, timeout)
            except ProtocolError:
                self.pool.discard(conn)
                raise
            except TimeoutError:
                self.pool.discard(conn)
                raise ProtocolError(f"timeout waiting for response from {key.target}") from None
            except (asyncio.IncompleteReadError, OSError, ConnectionError):
                self.pool.discard(conn)
                raise
            else:
                self.pool.release(conn)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RawExchange(
            target=target, sent_frame=frame.hex(), received_frame=resp.hex(), elapsed_ms=elapsed_ms
        )


class FinsError(ProtocolError):
    """FINS 设备错误 (端结码非 0 / 畸形响应)。"""
