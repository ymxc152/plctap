"""Modbus TCP 协议元数据。"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="modbus",
    default_port=502,
    port_hints=[502, 1502, 5020, 15020],
    addressing_model="register",
    summary="Modbus TCP (最通用的工业协议, 支持品牌最广)",
    data_types=["uint16", "int16", "float32"],
    vendor_hints=["Siemens", "Schneider", "Wago", "通用网关", "Modbus TCP 从站"],
    read_options={'function_code': '3=保持寄存器 (默认), 4=输入寄存器'},
)
