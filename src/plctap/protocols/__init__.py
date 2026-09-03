"""协议适配器子包 (插件式: Modbus / FINS / MELSEC)。"""

from __future__ import annotations

from types import ModuleType


def codec_for(protocol: str) -> ModuleType:
    """按协议名取 codec 纯函数模块 (parse_request/parse_response/validate_frame)。

    诊断引擎与评测共用的查找点; 新协议在此补一行映射。
    """
    if protocol == "modbus":
        from plctap.protocols.modbus import codec

        return codec
    if protocol == "fins":
        from plctap.protocols.fins import codec

        return codec
    if protocol == "melsec":
        from plctap.protocols.melsec import codec

        return codec
    raise KeyError(f"unknown protocol {protocol!r}")
