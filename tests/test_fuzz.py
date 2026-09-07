# -*- coding: utf-8 -*-
"""hypothesis 模糊测试: 喂随机与变异字节给 parse/validate 纯函数层 (v0.6 batch1)。

性质契约 ("畸形帧是诊断证据, 不是异常"):
  1. 恒不崩: 除 KNOWN_RAISES 白名单 (文档化契约 + 已登记缺陷) 外, 任意字节
     序列喂给任一 parse/validate 纯函数入口都不允许抛异常;
  2. 恒结构化: 正常返回必须是良构 ParseResult (valid == (not errors)) 或
     list[CheckResult] (每项 name 非空 / passed 为 bool)。

策略两档:
  - 随机: st.binary(0..512), 覆盖空帧/超短帧/超长帧;
  - 定向变异: 以 eval/corpus/*.yaml 与既有测试常量里的合法帧为种子, 做
    截断/位翻转/插入/重复/删除/覆盖 1-4 步 (字段错位的常见来源)。

profile (settings.register_profile):
  - ci   (默认): max_examples=50, derandomize=True —— 同一输入集, CI 不抖绿;
  - soak: 环境变量 PLCTAP_FUZZ_PROFILE=soak, max_examples=500,
    derandomize=False —— 本地浸泡, 每次探索新路径 (炸出新崩溃按报告归档)。
  deadline=None: Windows 计时抖动, 不做单例时限。

KNOWN_RAISES 白名单分两类 (修复 src 后应同步删除对应条目并收紧):
  - 文档化契约: s7.parse_request 对 <17B 抛 ValueError (docstring 明示
    "畸形帧不抛错 (除无法定位 S7 头外)");
  - 本轮 fuzz 发现的缺陷: 机制见各条注释, 最小复现钉在
    test_known_crash_signatures_pinned (修复后该测试依旧全绿)。
"""

from __future__ import annotations

import os
import struct

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import ValidationError

from plctap.models import CheckResult, ParseResult
from plctap.protocols.auto import parse_auto
from plctap.protocols.enip import codec as enip_codec
from plctap.protocols.fins import codec as fins_codec
from plctap.protocols.iec104 import codec as iec104_codec
from plctap.protocols.melsec import codec as melsec_codec
from plctap.protocols.modbus import codec as modbus_codec
from plctap.protocols.s7 import codec as s7_codec


# ---------------------------------------------------------------- hypothesis profile

def _load_fuzz_profile() -> str:
    """注册并加载 profile: 默认 ci (快/确定性), PLCTAP_FUZZ_PROFILE=soak 提升到 500。"""
    settings.register_profile(
        "ci",
        max_examples=50,
        deadline=None,
        derandomize=True,  # 固定输入集: CI 结果可复现, 不因随机种子抖绿
        suppress_health_check=[HealthCheck.too_slow],
        print_blob=True,
    )
    settings.register_profile(
        "soak",
        max_examples=500,
        deadline=None,
        derandomize=False,  # 每次换种子: 浸泡探索新崩溃路径
        suppress_health_check=[HealthCheck.too_slow],
        print_blob=True,
    )
    name = os.environ.get("PLCTAP_FUZZ_PROFILE", "ci").strip().lower()
    settings.load_profile(name if name in ("ci", "soak") else "ci")
    return name


_FUZZ_PROFILE = _load_fuzz_profile()


# ---------------------------------------------------------------- 已知异常白名单

# key = 纯函数入口标签 (与 _call 的 label 一致), value = 允许抛出的异常类型。
# 未登记的入口一律不许抛 (strict); 修复 src 后删除对应条目即可收紧。
KNOWN_RAISES: dict[str, tuple[type[BaseException], ...]] = {
    # 文档化契约: <17B 抛 ValueError ("除无法定位 S7 头外", docstring 明示)。
    # 另含本轮 fuzz 发现的写数据区缺陷 (修复后可删): FUNC_WRITE_VAR 且
    # data_len∈1..3、尾部数据恰好等长时 -> d[1] IndexError / unpack_from struct.error。
    "s7.parse_request": (ValueError, struct.error, IndexError),
    # 缺陷: binary 请求 data 恰 4~7B 时 _decode_pdu 的 data[7] 越界 -> IndexError;
    #       ASCII 请求 PDU 区非 hex/非 ASCII 字符时 _dec_ascii/.decode -> ValueError
    #       (UnicodeDecodeError 是 ValueError 子类, 一并覆盖)。
    "melsec.parse_request_fmt": (ValueError, IndexError),
    # 缺陷: ASCII 响应端结码为 0 且尾部字值区非 hex 时 _decode_word_values -> ValueError。
    "melsec.parse_response_fmt": (ValueError,),
    # 缺陷: ASCII 格式 sub/data_length/end_code 字段非 hex 时 _dec_ascii -> ValueError。
    "melsec.validate_frame_fmt": (ValueError,),
    # 缺陷: U 格式功能码不认识 (非 STARTDT/STOPDT/TESTFR) 时 direction 保持 "auto",
    #       ParseResult(direction="auto") 被 pydantic Literal 拒绝 -> ValidationError。
    "iec104.parse_frame": (ValidationError,),
    # 缺陷: ListIdentity/SendRRData 载荷截断到 item 边界之前时
    #       struct.unpack_from 越界 -> struct.error。
    "enip.parse_request": (struct.error,),
    "enip.parse_response": (struct.error,),
    # parse_auto 内部分派到上述入口, 继承同一组白名单。
    "parse_auto[melsec]": (ValueError, IndexError),
    "parse_auto[iec104]": (ValidationError,),
    "parse_auto[enip]": (struct.error,),
}


def _call(label: str, fn, frame: bytes):
    """白名单守卫调用: 白名单外异常转 AssertionError 抛给 hypothesis (失败 + 收缩);
    白名单内异常返回 None (视为已登记缺陷, 不做结构断言); 正常返回原结果。"""
    allowed = KNOWN_RAISES.get(label)
    try:
        return fn(frame)
    except Exception as e:  # noqa: BLE001
        if allowed is not None and isinstance(e, tuple(allowed)):
            return None
        raise AssertionError(
            f"{label} 对畸形帧抛了白名单外异常 {type(e).__name__}: {e}; "
            f"frame(hex)={frame.hex()}"
        ) from e


def _assert_well_formed(result) -> None:
    """结构化契约: ParseResult 自洽 / CheckResult 清单良构。"""
    if isinstance(result, ParseResult):
        assert result.direction in ("req", "resp")
        assert result.valid == (not result.errors), "valid 必须等于 not errors"
        for f in result.fields:
            assert f.byte_offset >= 0
            assert isinstance(f.raw_hex, str)
        return
    assert isinstance(result, list), f"期望 list[CheckResult], 得到 {type(result)}"
    for c in result:
        assert isinstance(c, CheckResult)
        assert c.name
        assert isinstance(c.passed, bool)


# ---------------------------------------------------------------- 合法帧种子

# 来源: eval/corpus/*.yaml、tests/test_*.py 常量、codec builder 生成 (逐帧验证 valid=True)。
MODBUS_TCP_SEEDS = [
    "12340000000601030000000a",      # test_codec_modbus READ_REQ_FC3
    "00010000000701030401020304",    # test_smoke READ_RESP
    "000100000003018302",            # test_smoke EXC_RESP (异常响应)
    "000600000006012f00000000",      # eval/corpus/modbus_m2.yaml
]
MODBUS_RTU_SEEDS = [
    "01030000000184f5",              # eval/corpus (RTU 读保持寄存器)
    "010300000001840a",              # eval/corpus (同帧坏 CRC 轨道)
    "018302c0f1",                    # eval/corpus (RTU 异常响应)
    "0183023ff1",
    "0103",                          # eval/corpus (半帧)
]
FINS_SEEDS = [
    "46494e53000000160000000400000000c000020000000002000101011101",  # corpus 数据交换读响应
    "46494e53000000160000000400000000c000020000000002000101010205",  # corpus 数据交换读请求
    "46494e5300000012000000040000000100000000000000000000",          # corpus 握手确认
    "46494e5300000012000000990000000000000000000000000000",          # corpus error 字段变体
]
# melsec 4 种帧格式各自的请求/写/响应种子 (由 codec builder 生成并验证)。
MELSEC_SEEDS = {
    "3e_binary": [
        "500000ffff03000c00040001040000640000a80200",        # 0401 批量读 D100 x2
        "500000ffff03001000040001140000640000a8020034127856",  # 1401 批量写
        "d00000ffff03000600000002010403",                    # 端结码 0 + 2 字值
        "d00000ffff030002004fc0",                            # eval/corpus (端结码非 0)
    ],
    "3e_ascii": [
        "500000FF03FF000018000404010000D*0001000002".encode("ascii"),
        "D00000FF03FF00000C000001020304".encode("ascii"),
    ],
    "4e_binary": [
        "54000000000000ffff03000c00040001040000640000a80200",
        "d4000100000000ffff03000600000002010403",
    ],
    "4e_ascii": [
        "54000000000000FF03FF000018000404010000D*0001000002".encode("ascii"),
        "D4000001000000FF03FF00000C000001020304".encode("ascii"),
    ],
}
S7_SEEDS = [
    "0300001f02f080320100000001000e00000401120a10020004000184005250",  # test_smoke S7_READ_REQ
    "0300001d02f0803203000000010002001f00000401ff04000441970a3d",      # test_smoke S7_READ_RSP
]
IEC104_SEEDS = [
    "680e0000000064010600010000000014",  # corpus I 格式总召唤
    "680e04000100010103000100c8000001",  # corpus I 格式遥测
    "680407000000",                      # corpus U 格式
]
ENIP_SEEDS = [
    "650004000000000000000000706c6374617000000000000001000000",  # corpus RegisterSession
    "630000000000000000000000706c63746170000000000000",          # corpus ListIdentity
    "6f0015000010000000000000706c63746170000000000000"
    "000000000000020000000000b1000500cc00050000",                # corpus SendRRData (CIP 应答)
]

_RANDOM_BYTES = st.binary(min_size=0, max_size=512)  # 空/超短/超长全覆盖


def _mutate(frame: bytes, data) -> bytes:
    """对合法帧做 1-4 步定向变异: 截断/位翻转/插入/重复/删除/覆盖。"""
    out = bytearray(frame)
    for _ in range(data.draw(st.integers(min_value=1, max_value=4))):
        if not out:  # 变异中途截成空帧: 补一段垃圾继续
            out += data.draw(st.binary(min_size=1, max_size=8))
            continue
        pos = data.draw(st.integers(min_value=0, max_value=len(out)))
        op = data.draw(st.sampled_from(["truncate", "flip", "insert", "duplicate", "delete", "overwrite"]))
        if op == "truncate":
            # 截断: 丢尾部 (半帧是诊断信息, parse_pcap 也按 partial 收)
            out = out[: data.draw(st.integers(min_value=0, max_value=len(out)))]
        elif op == "flip":
            i = data.draw(st.integers(min_value=0, max_value=len(out) - 1))
            out[i] ^= data.draw(st.integers(min_value=1, max_value=255))
        elif op == "insert":
            out[pos:pos] = data.draw(st.binary(min_size=1, max_size=8))
        elif op == "duplicate":
            # 重复既有片段: 制造字段错位/长度字段与实际不符
            i = data.draw(st.integers(min_value=0, max_value=len(out) - 1))
            j = data.draw(st.integers(min_value=i + 1, max_value=len(out)))
            out[pos:pos] = out[i:j]
        elif op == "delete":
            pos = min(pos, len(out) - 1)  # 尾端删除退化为去最后一字节, 保证区间非空
            j = data.draw(st.integers(min_value=pos + 1, max_value=len(out)))
            del out[pos:j]
        else:
            payload = data.draw(st.binary(min_size=1, max_size=8))
            out[pos : pos + len(payload)] = payload
    return bytes(out)


def _seed_frames(hexes: list) -> list[bytes]:
    """hex 串转字节; melsec ASCII 帧种子本身就是线字节 (ASCII 文本), 原样保留。"""
    return [h if isinstance(h, bytes) else bytes.fromhex(h) for h in hexes]


# ---------------------------------------------------------------- modbus (TCP + RTU 同轨)


class TestModbusFuzz:
    @given(frame=_RANDOM_BYTES)
    def test_tcp_random_bytes(self, frame):
        """随机字节 -> modbus TCP 双向 parse + validate 恒结构化。"""
        r = _call("modbus.parse_request", modbus_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("modbus.parse_response", modbus_codec.parse_response, frame)
        if r is not None:
            _assert_well_formed(r)
        for d in ("req", "resp"):
            _assert_well_formed(modbus_codec.validate_frame(frame, d))

    @given(frame=_RANDOM_BYTES)
    def test_rtu_random_bytes(self, frame):
        """随机字节 -> RTU 轨道 (CRC 判别与 TCP 不同) parse/validate 恒结构化。"""
        r = _call("modbus.parse_rtu", modbus_codec.parse_rtu, frame)
        if r is not None:
            _assert_well_formed(r)
        _assert_well_formed(modbus_codec.validate_rtu(frame))

    @given(data=st.data())
    def test_mutated_seeds(self, data):
        """合法 TCP/RTU 帧定向变异 -> 全部 modbus 入口恒结构化。"""
        seeds = _seed_frames(MODBUS_TCP_SEEDS + MODBUS_RTU_SEEDS)
        frame = _mutate(data.draw(st.sampled_from(seeds)), data)
        r = _call("modbus.parse_request", modbus_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("modbus.parse_response", modbus_codec.parse_response, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("modbus.parse_rtu", modbus_codec.parse_rtu, frame)
        if r is not None:
            _assert_well_formed(r)
        _assert_well_formed(modbus_codec.validate_frame(frame, "resp"))
        _assert_well_formed(modbus_codec.validate_rtu(frame))


# ---------------------------------------------------------------- fins


class TestFinsFuzz:
    @given(frame=_RANDOM_BYTES)
    def test_random_bytes(self, frame):
        """随机字节 -> FINS/TCP 双向 parse + validate 恒结构化。"""
        r = _call("fins.parse_request", fins_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("fins.parse_response", fins_codec.parse_response, frame)
        if r is not None:
            _assert_well_formed(r)
        for d in ("req", "resp"):
            _assert_well_formed(fins_codec.validate_frame(frame, d))

    @given(data=st.data())
    def test_mutated_seeds(self, data):
        """合法 FINS/TCP 帧定向变异 (含非标 cmd=0x99 变体) -> 恒结构化。"""
        frame = _mutate(data.draw(st.sampled_from(_seed_frames(FINS_SEEDS))), data)
        r = _call("fins.parse_request", fins_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("fins.parse_response", fins_codec.parse_response, frame)
        if r is not None:
            _assert_well_formed(r)
        _assert_well_formed(fins_codec.validate_frame(frame, "resp"))


# ---------------------------------------------------------------- melsec (3E/4E x binary/ASCII)


class TestMelsecFuzz:
    @given(frame=_RANDOM_BYTES)
    def test_random_bytes_all_formats(self, frame):
        """随机字节 -> 4 种帧格式 x 请求/响应/校验 恒结构化 (白名单见 KNOWN_RAISES)。"""
        for fmt in melsec_codec.FRAME_FORMATS:
            r = _call("melsec.parse_request_fmt", lambda f, fm=fmt: melsec_codec.parse_request_fmt(f, fm), frame)
            if r is not None:
                _assert_well_formed(r)
            r = _call("melsec.parse_response_fmt", lambda f, fm=fmt: melsec_codec.parse_response_fmt(f, frame_format=fm), frame)
            if r is not None:
                _assert_well_formed(r)
            for d in ("req", "resp"):
                checks = _call("melsec.validate_frame_fmt", lambda f, fm=fmt, dd=d: melsec_codec.validate_frame_fmt(f, dd, frame_format=fm), frame)
                if checks is not None:
                    _assert_well_formed(checks)

    @given(data=st.data())
    def test_mutated_seeds(self, data):
        """各格式合法帧定向变异 -> parse/validate 恒结构化 (ASCII 崩溃路径被白名单覆盖)。"""
        fmt = data.draw(st.sampled_from(melsec_codec.FRAME_FORMATS))
        frame = _mutate(data.draw(st.sampled_from(_seed_frames(MELSEC_SEEDS[fmt]))), data)
        r = _call("melsec.parse_request_fmt", lambda f, fm=fmt: melsec_codec.parse_request_fmt(f, fm), frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("melsec.parse_response_fmt", lambda f, fm=fmt: melsec_codec.parse_response_fmt(f, frame_format=fm), frame)
        if r is not None:
            _assert_well_formed(r)
        for d in ("req", "resp"):
            checks = _call("melsec.validate_frame_fmt", lambda f, fm=fmt, dd=d: melsec_codec.validate_frame_fmt(f, dd, frame_format=fm), frame)
            if checks is not None:
                _assert_well_formed(checks)


# ---------------------------------------------------------------- s7


class TestS7Fuzz:
    @given(frame=_RANDOM_BYTES)
    def test_random_bytes(self, frame):
        """随机字节 -> S7 请求/读响应/校验 恒结构化 (<17B ValueError 属文档化契约)。"""
        r = _call("s7.parse_request", s7_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("s7.parse_read_response", s7_codec.parse_read_response, frame)
        if r is not None:
            _assert_well_formed(r)
        for d in ("req", "resp"):
            _assert_well_formed(s7_codec.validate_frame(frame, d))

    @given(data=st.data())
    def test_mutated_seeds(self, data):
        """合法 S7 请求/响应定向变异 -> 恒结构化 (写数据区缺陷被白名单覆盖)。"""
        frame = _mutate(data.draw(st.sampled_from(_seed_frames(S7_SEEDS))), data)
        r = _call("s7.parse_request", s7_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("s7.parse_read_response", s7_codec.parse_read_response, frame)
        if r is not None:
            _assert_well_formed(r)
        _assert_well_formed(s7_codec.validate_frame(frame, "resp"))


# ---------------------------------------------------------------- iec104


class TestIec104Fuzz:
    @given(frame=_RANDOM_BYTES)
    def test_random_bytes(self, frame):
        """随机字节 -> I/S/U 三帧型 parse + validate 恒结构化 (U 未知功能码缺陷被白名单覆盖)。"""
        r = _call("iec104.parse_frame", iec104_codec.parse_frame, frame)
        if r is not None:
            _assert_well_formed(r)
        for d in ("req", "resp"):
            _assert_well_formed(iec104_codec.validate_frame(frame, d))

    @given(data=st.data())
    def test_mutated_seeds(self, data):
        """合法 I/U 帧定向变异 -> 恒结构化。"""
        frame = _mutate(data.draw(st.sampled_from(_seed_frames(IEC104_SEEDS))), data)
        r = _call("iec104.parse_frame", iec104_codec.parse_frame, frame)
        if r is not None:
            _assert_well_formed(r)
        _assert_well_formed(iec104_codec.validate_frame(frame, "resp"))


# ---------------------------------------------------------------- enip


class TestEnipFuzz:
    @given(frame=_RANDOM_BYTES)
    def test_random_bytes(self, frame):
        """随机字节 -> ENIP 封装 + CIP 双向 parse + validate 恒结构化。"""
        r = _call("enip.parse_request", enip_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("enip.parse_response", enip_codec.parse_response, frame)
        if r is not None:
            _assert_well_formed(r)
        for d in ("req", "resp"):
            _assert_well_formed(enip_codec.validate_frame(frame, d))

    @given(data=st.data())
    def test_mutated_seeds(self, data):
        """合法 Register/ListIdentity/SendRRData 定向变异 -> 恒结构化 (item 截断缺陷被白名单覆盖)。"""
        frame = _mutate(data.draw(st.sampled_from(_seed_frames(ENIP_SEEDS))), data)
        r = _call("enip.parse_request", enip_codec.parse_request, frame)
        if r is not None:
            _assert_well_formed(r)
        r = _call("enip.parse_response", enip_codec.parse_response, frame)
        if r is not None:
            _assert_well_formed(r)
        _assert_well_formed(enip_codec.validate_frame(frame, "resp"))


# ---------------------------------------------------------------- parse_auto (server.parse_frame 的 auto 轨道)


class TestParseAutoFuzz:
    @given(frame=_RANDOM_BYTES, protocol=st.sampled_from(["modbus", "fins", "melsec", "iec104", "enip"]))
    def test_random_bytes(self, protocol, frame):
        """随机字节 -> parse_auto 五协议方向自动判别恒结构化。"""
        r = _call(f"parse_auto[{protocol}]", lambda f, p=protocol: parse_auto(p, f), frame)
        if r is not None:
            _assert_well_formed(r)

    @given(data=st.data(), protocol=st.sampled_from(["modbus", "fins", "melsec", "iec104", "enip"]))
    def test_mutated_seeds(self, protocol, data):
        """各协议合法帧定向变异 -> parse_auto 恒结构化 (melsec binary IndexError 走 auto 亦可复现)。"""
        seeds = {
            "modbus": MODBUS_TCP_SEEDS,
            "fins": FINS_SEEDS,
            "melsec": [h for frames in MELSEC_SEEDS.values() for h in frames],
            "iec104": IEC104_SEEDS,
            "enip": ENIP_SEEDS,
        }[protocol]
        frame = _mutate(data.draw(st.sampled_from(_seed_frames(seeds))), data)
        r = _call(f"parse_auto[{protocol}]", lambda f, p=protocol: parse_auto(p, f), frame)
        if r is not None:
            _assert_well_formed(r)

    def test_unsupported_protocol_documented(self):
        """文档化契约: parse_auto 未覆盖的协议抛 ValueError (server 层 s7 走独立分支)。"""
        with pytest.raises(ValueError, match="not implemented"):
            parse_auto("s7", b"\x03\x00\x00\x19")
        with pytest.raises(ValueError, match="not implemented"):
            parse_auto("modbus_rtu", b"\x01\x03\x00\x00\x00\x01\x84\xf5")


# ---------------------------------------------------------------- 已知崩溃签名回归钉


def test_known_crash_signatures_pinned():
    """本轮 fuzz 命中的已知缺陷最小复现帧 (可执行清单, 供修复后回归)。

    每条钉两层: ① 白名单外不许抛 (白名单扩大必须显式改 KNOWN_RAISES);
    ② 修复后返回良构结构化结果, 本测试依旧全绿 —— 届时删除白名单条目。
    """
    pins: list[tuple[str, object, bytes]] = [
        # melsec 3E binary 请求: data 恰 5B (4<=len<8) -> _decode_pdu data[7] IndexError
        ("melsec.parse_request_fmt",
         lambda f: melsec_codec.parse_request_fmt(f, "3e_binary"),
         bytes.fromhex("500000000000000000000001020304")),
        # melsec 3E ASCII 请求: 头部合法 hex + PDU 区 'ZZZZZZZZ' -> _dec_ascii ValueError
        ("melsec.parse_request_fmt",
         lambda f: melsec_codec.parse_request_fmt(f, "3e_ascii"),
         "500000FF03FF0000100004ZZZZZZZZ".encode("ascii")),
        # melsec 3E ASCII 响应: 端结码 0 + 字值区 'ZZZZ' -> _decode_word_values ValueError
        ("melsec.parse_response_fmt",
         lambda f: melsec_codec.parse_response_fmt(f, frame_format="3e_ascii"),
         "D00000FF03FF00000C0000ZZZZ".encode("ascii")),
        # melsec 3E ASCII 校验: data_length 字段 'ZZZZ' -> ValueError; 非 ASCII 头 -> UnicodeDecodeError
        ("melsec.validate_frame_fmt",
         lambda f: melsec_codec.validate_frame_fmt(f, "req", frame_format="3e_ascii"),
         "500000FF03FF00ZZZZ0004".encode("ascii")),
        ("melsec.validate_frame_fmt",
         lambda f: melsec_codec.validate_frame_fmt(f, "req", frame_format="3e_ascii"),
         bytes.fromhex("2b5df1f0")),
        # s7: <17B -> 文档化 ValueError; 写数据 data_len=3 尾差 1B -> struct.error; data_len=1 -> IndexError
        ("s7.parse_request", s7_codec.parse_request, bytes.fromhex("0300001f02f0")),
        ("s7.parse_request", s7_codec.parse_request,
         bytes.fromhex("0300001400f000320100000001000300020500aabbcc")),
        ("s7.parse_request", s7_codec.parse_request,
         bytes.fromhex("0300001400f000320100000001000300010500aa")),
        # iec104: U 格式功能码 0xAA 未收录 -> direction 停留 "auto" -> pydantic ValidationError
        ("iec104.parse_frame", iec104_codec.parse_frame, bytes.fromhex("6804aad62def99e87a")),
        # enip: SendRRData item_count=2 但 CIP 载荷截断 -> struct.error; ListIdentity 24B 整 -> struct.error
        ("enip.parse_request", enip_codec.parse_request,
         bytes.fromhex("6f0015000010000000000000706c637461700000000000000000000000000200")),
        ("enip.parse_response", enip_codec.parse_response,
         bytes.fromhex("630000000000000000000000706c77746170000000000000")),
    ]
    for label, fn, frame in pins:
        result = _call(label, fn, frame)
        if result is not None:  # 修复后路径: 必须是良构结构化结果
            _assert_well_formed(result)
