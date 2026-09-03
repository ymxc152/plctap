"""三协议共享的纯函数工具 (无 I/O)。

interpret_registers 从 Modbus codec 上移至此: FINS (默认大端) 与
MC (默认小端) 的 datatype 解释逻辑完全一致 —— 差异只在默认字节序,
而字节序已参数化 (D2: 纯函数复用, 也是知识库的"字节序陷阱"素材)。
"""

from __future__ import annotations

import struct
from typing import Sequence

from plctap.models import ByteOrder


def interpret_registers(
    raw: Sequence[int],
    datatype: str | None = None,
    byteorder: ByteOrder = "big",
) -> list[float | int]:
    """把 16 位寄存器原始值按 datatype 解释。

    - uint16/int16: 每寄存器一个值 (int16 做补码转换)
    - float32: 两个连续寄存器合成一个 32 位值, byteorder 决定组合:
      "big" = 高字在前、字内大端 (ABCD); "little" = 低字在前、字内小端 (DCBA)。
      字交换等其它厂商变体 (如 CDAB) 由知识库描述, 需要时再作为显式档位加入。
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
