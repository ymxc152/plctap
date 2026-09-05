"""Omron FINS/TCP 协议元数据。"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="fins",
    default_port=9600,
    port_hints=[9600, 9601],
    addressing_model="memory_area",
    summary="Omron FINS/TCP (欧姆龙 PLC 专用, 端口 9600)",
    data_types=["uint16", "int16", "float32"],
    vendor_hints=["Omron", "欧姆龙", "OMRON", "Sysmac"],
    read_options={'area': 'CIO/W/H/A/DM/EM (默认 DM)'},
)
