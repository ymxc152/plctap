# -*- coding: utf-8 -*-
"""hypothesis 模糊测试: 喂随机与变异字节给 parse/validate 纯函数层 (v0.6 batch1)。

性质契约 ("畸形帧是诊断证据, 不是异常"):
  1. 恒不崩: 除 KNOWN_RAISES 白名单 (仅文档化契约) 外, 任意字节序列喂给
     任一 parse/validate 纯函数入口都不允许抛异常;
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

KNOWN_RAISES 白名单只允许文档化契约 (docstring 明示的异常):
  s7.parse_request 对 <17B 帧抛 ValueError。首轮 fuzz 登记的 7 处缺陷已于
  v0.6 修复并移出白名单, 最小复现帧固化为显式回归断言:
  test_former_defect_frames_now_structured (断言具体 errors 内容而非只不炸)。
"""

from __future__ import annotations

import os
import struct

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

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
# 仅保留文档化契约 (docstring 明示的异常); 缺陷类条目已随 v0.6 修复全部移除 ——
# 新增条目必须注明出处, 且优先修 src 而不是扩白名单。
KNOWN_RAISES: dict[str, tuple[type[BaseException], ...]] = {
    # 文档化契约: s7.parse_request 对 <17B 帧抛 ValueError
    # (docstring 明示 "畸形帧不抛错 (除无法定位 S7 头外)")。
    "s7.parse_request": (ValueError,),
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


# ---------------------------------------------------------------- 已修复缺陷的显式回归


def test_former_defect_frames_now_structured():
    """v0.6 fuzz 命中并已修复的缺陷最小复现帧: 逐帧断言结构化结果与具体 errors 内容。

    这些帧曾经让 codec 抛 IndexError/ValueError/struct.error/ValidationError
    (机制见各断言注释); 修复后必须返回 valid=False 的结构化证据, 而不只是不炸。
    """
    # --- melsec: binary 请求 data 恰 4~7B, 曾在 _decode_pdu data[7] IndexError ---
    r = melsec_codec.parse_request_fmt(bytes.fromhex("500000000000000000000001020304"), "3e_binary")
    assert r.direction == "req" and not r.valid
    assert any("request data too short for device block" in e for e in r.errors), r.errors

    # --- melsec: ASCII 请求软元件区 20 字符非 hex, 曾 _dec_ascii ValueError ---
    r = melsec_codec.parse_request_fmt(("500000FF03FF0000180004" + "Z" * 20).encode("ascii"),
                                       "3e_ascii")
    assert not r.valid
    assert any("device block undecodable" in e for e in r.errors), r.errors

    # --- melsec: ASCII 响应端结码 0 + 字值区非 hex, 曾 _decode_word_values ValueError ---
    r = melsec_codec.parse_response_fmt("D00000FF03FF00000C0000ZZZZ".encode("ascii"),
                                        frame_format="3e_ascii")
    assert not r.valid
    assert any("word values undecodable" in e for e in r.errors), r.errors

    # --- melsec validate: ASCII data_length 字段非 hex -> 失败项留 raw 证据, 不抛 ---
    checks = {c.name: c for c in melsec_codec.validate_frame_fmt(
        "500000FF03FF00ZZZZ0004".encode("ascii"), "req", frame_format="3e_ascii")}
    assert not checks["data_length_consistent"].passed
    assert "not ASCII hex" in checks["data_length_consistent"].detail

    # --- melsec validate: ASCII 副头部非 ASCII 字节, 曾 UnicodeDecodeError ---
    checks = {c.name: c for c in melsec_codec.validate_frame_fmt(
        bytes.fromhex("2b5df1f0"), "req", frame_format="3e_ascii")}
    assert not checks["subheader_3e_ascii"].passed
    assert "not ASCII hex" in checks["subheader_3e_ascii"].detail
    assert not checks["subheader_match"].passed

    # --- s7: 写数据 data_len=2 尾差 1B 曾 struct.error; data_len=1 曾 d[1] IndexError ---
    r = s7_codec.parse_request(bytes.fromhex("0300001400f000320100000001000300020500aabbcc"))
    assert r.direction == "req" and not r.valid
    assert any("write data header truncated: have 3, need 4" in e for e in r.errors), r.errors
    r = s7_codec.parse_request(bytes.fromhex("0300001400f000320100000001000300010500aa"))
    assert any("write data header truncated: have 1, need 4" in e for e in r.errors), r.errors

    # --- iec104: I 格式 ASDU 截到 9B 曾 direction="auto" 被 pydantic 拒绝;
    #     现按监视方向兜底 (与未知 type 一致), 截断留 "ASDU too short" 证据 ---
    r = iec104_codec.parse_frame(bytes.fromhex("6804aad62def99e87a"))
    assert r.direction == "resp" and not r.valid
    assert any("ASDU too short" in e for e in r.errors), r.errors

    # --- iec104: 未知 U 功能码进 errors (方向按主站发起兜底 req), 不掩盖功能码证据 ---
    r = iec104_codec.parse_frame(bytes.fromhex("680403000000"))
    assert r.direction == "req" and not r.valid
    assert any("unknown U-function 0x03" in e for e in r.errors), r.errors
    ufn = next(f for f in r.fields if f.name == "u_function")
    assert ufn.value == 0x03 and ufn.note == "UNKNOWN_U_0x03"

    # --- enip: RRData 请求载荷逐段截断, 曾 struct.error; 现转 errors ---
    def _rrdata_req(payload: bytes) -> bytes:
        return struct.pack("<HHII8sI", 0x006F, len(payload), 0, 0, b"plctap\x00\x00", 0) + payload

    r = enip_codec.parse_request(_rrdata_req(struct.pack("<IHH", 0, 0, 2)))  # 缺地址项头
    assert r.direction == "req" and not r.valid
    assert any("address item truncated" in e for e in r.errors), r.errors
    r = enip_codec.parse_request(_rrdata_req(struct.pack("<IHHHH", 0, 0, 2, 0, 0)))  # 缺数据项头
    assert any("data item header truncated" in e for e in r.errors), r.errors
    r = enip_codec.parse_request(
        _rrdata_req(struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0, 0)
                    + struct.pack("<HH", 0x00B2, 4)))  # 数据项体截断
    assert any("data item truncated: have 0, need 4" in e for e in r.errors), r.errors

    # --- enip: ListIdentity 应答恰 24B, 曾 item_count unpack struct.error ---
    frame = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"plctap\x00\x00", 0)
    r = enip_codec.parse_response(frame)
    assert r.direction == "resp" and not r.valid
    assert any("identity item count truncated" in e for e in r.errors), r.errors

    # --- enip: RegisterSession 应答恰 24B, 曾 version/options unpack struct.error ---
    frame = struct.pack("<HHII8sI", 0x0065, 0, 0, 0, b"plctap\x00\x00", 0)
    r = enip_codec.parse_response(frame)
    assert not r.valid
    assert any("register session payload truncated" in e for e in r.errors), r.errors

    # --- enip: 身份体截断 (<35B), 曾 body[off] IndexError ---
    ident = struct.pack("<HH", enip_codec.ITEM_CIP_IDENTITY, 8) + b"\x01\x00" + b"\x00" * 14
    payload = struct.pack("<H", 1) + ident  # item_count + 身份项
    frame = struct.pack("<HHII8sI", 0x0063, len(payload), 0, 0, b"plctap\x00\x00", 0) + payload
    r = enip_codec.parse_response(frame)
    assert not r.valid
    assert any("identity body truncated" in e for e in r.errors), r.errors
