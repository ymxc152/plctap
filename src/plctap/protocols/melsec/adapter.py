"""Mitsubishi MELSEC MC 3E 二进制适配器 (M2)。

MC/3E 是无会话协议: 每帧自描述 (副头部+网络/PC 回显), 无握手、无事务号,
直接走通用 locked_exchange。可靠性靠响应与请求的头部回显交叉核对
(codec._cross_check), 这是 3E 场景串包检测的主要手段 —— 也是诊断引擎
的重要素材 (网络号/PC 号配置不符时回显错位)。
"""

from __future__ import annotations

import asyncio
import struct
import time

from plctap.models import (
    ByteOrder,
    ProbeResult,
    RawExchange,
    ReadResult,
    Target,
)
from plctap.protocols.base import (
    ProtocolAdapter,
    ProtocolError,
    locked_exchange,
    recv_exact,
    register_adapter,
)
from plctap.protocols.melsec import codec
from plctap.protocols.melsec import meta as _meta

FRAME_HEADER_LEN = codec.FRAME_HEADER_LEN


@register_adapter
class MelsecAdapter(ProtocolAdapter):
    name = "melsec"
    meta = _meta.META

    # ------------------------------------------------------------ 收帧

    async def _recv_frame(
        self, reader: asyncio.StreamReader, timeout: float, frame_format: str = "3e_binary"
    ) -> bytes:
        """按响应数据长度字段收一帧。支持全部 4 种 MELSEC 帧格式。

        响应: 数据长字段在 dl_off (3E 7 / 4E 11), 之后为结束代码+数据,
        总长 = dl_off + 2 + data_len。副头部应为 D0 00 (3E) / D4 00 (4E)。
        """
        dl_off = codec._DATALEN_OFFSETS[frame_format]
        head = await recv_exact(reader, dl_off + 2, timeout)
        (data_len,) = struct.unpack_from("<H", head, dl_off)
        (sub,) = struct.unpack_from(">H", head, 0)
        expected_sub = codec._RESP_SUBHEADERS[frame_format]
        if sub != expected_sub:
            raise ProtocolError(
                f"bad {frame_format} response subheader {sub:#06x} (expected {expected_sub:#06x}), stream out of sync"
            )
        if not 2 <= data_len <= 0x2000:
            raise ProtocolError(f"implausible {frame_format} data_length {data_len}, aborting read")
        payload = await recv_exact(reader, data_len, timeout)
        return head + payload

    # ------------------------------------------------------------ probe

    async def probe(self, target: Target) -> ProbeResult:
        """probe 不走连接池 (与 Modbus/FINS 同理): 一次性连接读 D0 一个字。"""
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
            request = codec.build_read_request("D", 0, 2)  # 读 2 字: 部分从站实现 (如开源 plc-simulator) 对 1 字读有越界 bug
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout)
            resp = await self._recv_frame(reader, timeout)
        except (ProtocolError, TimeoutError, asyncio.IncompleteReadError, OSError, ConnectionError):
            # TCP 已建立但没完成一次完整协议交互
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply", layer_hint="protocol")
        finally:
            writer.close()
        parsed = codec.parse_response_fmt(resp, request=request, frame_format="3e_binary")
        end_field = next((f for f in parsed.fields if f.name == "end_code"), None)
        if end_field is None or not parsed.valid:
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
        device: str = "D",
        frame_format: str = "3e_binary",
    ) -> ReadResult:
        """读软元件 (0401 批量读, 字单位)。

        device: D/R/W 为字软元件; X/Y/B/M 为位软元件 (按字读, 每字 16 点,
        字节序无意义)。byteorder 语义: MC 线上数据是小端, codec 解出的
        word_values 已按小端成 16 位整数; datatype=float32 时 little =
        低字在前 (MC 原生), big = 高字在前 (多数组态软件导出顺序)。
        默认 big 与 Modbus 工具语义对齐。
        """
        timeout = self.timeout(timeout_ms)
        request = codec.build_read_request(device, address, count, frame_format=frame_format)
        started = time.perf_counter()
        resp = await locked_exchange(
            self.pool, self.key_for(target), request, self._recv_frame, timeout
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        parsed = codec.parse_response_fmt(resp, request=request, frame_format=frame_format)
        end_field = next((f for f in parsed.fields if f.name == "end_code"), None)
        if end_field is None:
            raise McError("malformed response: no end code found; " + "; ".join(parsed.errors))
        end_code = end_field.value
        if isinstance(end_code, int) and end_code != 0:
            raise McError(
                f"device returned end code {codec.end_code_name(end_code)} ({end_code:#06x})"
                f" for device {device} head={address} count={count}"
            )
        if not parsed.valid:
            raise McError("malformed response: " + "; ".join(parsed.errors))
        values_field = next(f for f in parsed.fields if f.name == "word_values")
        raw = list(values_field.value)  # type: ignore[arg-type]
        expected_words = (count + 15) // 16 if device in codec.BIT_DEVICES else count
        if len(raw) < expected_words:
            raise McError(f"device returned {len(raw)} words, requested {expected_words}")
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
        resp = await locked_exchange(
            self.pool, self.key_for(target), frame, self._recv_frame, timeout
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RawExchange(
            target=target, sent_frame=frame.hex(), received_frame=resp.hex(), elapsed_ms=elapsed_ms
        )


class McError(ProtocolError):
    """MELSEC 设备错误 (结束代码非 0 / 畸形响应)。"""
