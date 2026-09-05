"""Mitsubishi MELSEC MC 协议元数据。"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="melsec",
    default_port=44818,
    port_hints=[44818, 5007],
    addressing_model="device",
    summary="Mitsubishi MELSEC 3E/4E binary+ASCII (三菱 Q/iQ-R 系列, TCP)",
    data_types=["uint16", "int16", "float32"],
    vendor_hints=["Mitsubishi", "三菱", "MELSEC", "Q 系列", "iQ-R"],
    read_options={"device": "D/R/W=字软元件, X/Y/B/M=位软元件16点 (默认 D)", "frame_format": "3e_binary|3e_ascii|4e_binary|4e_ascii (默认 3e_binary)"},
    write_options={"device": "默认 D; 位软元件按打包字写 (每字16点)", "frame_format": "3e_binary|3e_ascii|4e_binary|4e_ascii (默认 3e_binary)", "values": "16 位字列表 (1401 批量写)"},
)
