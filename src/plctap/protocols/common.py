"""三协议共享的纯函数工具 (无 I/O)。

interpret_registers 从 Modbus codec 上移至此: FINS (默认大端) 与
MC (默认小端) 的 datatype 解释逻辑完全一致 —— 差异只在默认字节序,
而字节序已参数化 (D2: 纯函数复用, 也是知识库的"字节序陷阱"素材)。
"""

from __future__ import annotations

import struct
from typing import Any, Sequence

from plctap.models import ByteOrder


def interpret_registers(
    raw: Sequence[int],
    datatype: str | None = None,
    byteorder: ByteOrder = "big",
) -> list[float | int]:
    """把 16 位寄存器原始值按 datatype 解释。

    - uint16/int16: 每寄存器一个值 (int16 做补码转换)
    - float32: 两个连续寄存器合成一个 32 位值, byteorder 决定组合:
      "big" = 高字在前、字内大端 (ABCD); "little" = 低字在前 (字交换 CDAB)。
      完整四种字序 (abcd/cdab/badc/dcba) 见 interpret_all 多解释表;
      显式按字交换读可通过 interpretations 自行对照, 无需二次读数。
    """
    if datatype is None:
        return list(raw)
    if datatype == "uint16":
        return list(raw)
    if datatype == "int16":
        return [v - 0x10000 if v >= 0x8000 else v for v in raw]
    if datatype == "float32":
        if len(raw) % 2 != 0:
            raise ValueError(
                f"float32 needs an even number of registers, got {len(raw)}"
            )
        out: list[float] = []
        for i in range(0, len(raw), 2):
            if byteorder == "big":
                b = raw[i].to_bytes(2, "big") + raw[i + 1].to_bytes(2, "big")
                (f,) = struct.unpack(">f", b)
            elif byteorder == "little":
                b = raw[i].to_bytes(2, "little") + raw[i + 1].to_bytes(2, "little")
                (f,) = struct.unpack("<f", b)
            else:
                raise ValueError(f"unknown byteorder {byteorder!r} (use 'big' or 'little')")
            out.append(f)
        return out
    raise ValueError(
        f"unknown datatype {datatype!r} (supported: uint16, int16, float32)"
    )


def interpret_all(raw: list[int]) -> dict[str, Any]:
    """把原始 16 位寄存器值按所有常见数据类型/字节序解释。

    用于 datatype=None 时让 Agent 一次看到所有可能解读, 避免猜错
    (D2 设计原则: "不猜, 把所有可能性摆出来")。

    float32 字序变体以 ABCD 字母命名 (工控组态软件的通用叫法, A = 最高
    字节): 两个寄存器 [w0, w1] 拆 4 字节后按不同排列组 32 位值 ——
    - abcd: 线序直读 (big-endian, 最常见)
    - cdab: 字交换 (不同组态软件导出的"小端字序")
    - badc: 字内字节交换
    - dcba: 全反 (full little-endian)
    字节序错配是现场最高频的"数值对不上"根因, 多解释表让 Agent 自主
    对照识别真实编码, 无需二次读数。

    返回字典 key = 数据类型_字节序, value = 解释后的值列表。
    float32_big / float32_little 为兼容旧 key (分别等价 abcd / cdab)。
    """
    result: dict[str, Any] = {}

    # 16 位逐寄存器
    result["uint16"] = list(raw)
    result["int16"] = [v - 0x10000 if v >= 0x8000 else v for v in raw]

    # 32 位组合 (仅偶数个寄存器时)
    if len(raw) >= 2 and len(raw) % 2 == 0:
        for order in ("abcd", "cdab", "badc", "dcba"):
            result[f"float32_{order}"] = _float32_word_order_all(raw, order)
        # 兼容旧 key: big = abcd, little = 字交换 (cdab, 非 dcba!)
        result["float32_big"] = result["float32_abcd"]
        result["float32_little"] = result["float32_cdab"]

        int32_big: list[int] = []
        int32_little: list[int] = []
        for i in range(0, len(raw), 2):
            hi, lo = raw[i], raw[i + 1]
            int32_big.append((hi << 16) | lo)
            int32_little.append((lo << 16) | hi)
        result["int32_big"] = int32_big
        result["int32_little"] = int32_little

    return result


def _float32_word_order_all(raw: Sequence[int], order: str) -> list[float]:
    out: list[float] = []
    for i in range(0, len(raw) - 1, 2):
        w0, w1 = raw[i], raw[i + 1]
        b = (w0 >> 8, w0 & 0xFF, w1 >> 8, w1 & 0xFF)
        layout = {
            "abcd": (b[0], b[1], b[2], b[3]),
            "cdab": (b[2], b[3], b[0], b[1]),
            "badc": (b[1], b[0], b[3], b[2]),
            "dcba": (b[3], b[2], b[1], b[0]),
        }[order]
        (f,) = struct.unpack(">f", bytes(layout))
        out.append(f)
    return out
