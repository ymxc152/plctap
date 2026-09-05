"""Siemens S7comm 协议元数据。"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="s7",
    default_port=102,
    port_hints=[102, 1020],
    addressing_model="memory_area",
    summary="Siemens S7comm (S7-200/300/400/1200/1500, TPKT+COTP+S7, TCP 102)",
    data_types=["uint16", "int16", "float32", "byte"],
    vendor_hints=["Siemens", "西门子", "S7", "S7-300", "S7-1200", "S7-1500", "STEP7", "TIA Portal"],
    read_options={"area": "DB|M|I|Q (默认 DB)", "db_number": "DB 块号 (仅 area=DB 有效, 默认 1)", "rack": "机架号 (默认 0)", "slot": "槽位号 (默认 1, S7-300 通常 2)"},
)
