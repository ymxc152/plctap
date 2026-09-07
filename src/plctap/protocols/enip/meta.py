"""EtherNet/IP (CIP) 协议元数据。"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="enip",
    default_port=44818,
    port_hints=[44818, 2222, 44818],
    addressing_model="tag",
    summary=(
        "EtherNet/IP / CIP (罗克韦尔 AB Logix 系列及 CIP 兼容设备, 44818; "
        "ENIP 封装 + 非连接消息读写 tag)"
    ),
    data_types=["uint16", "int16", "float32", "dint", "bool"],
    vendor_hints=[
        "Rockwell Allen-Bradley",
        "Omron NJ/NX",
        "CIP 兼容设备",
        "Logix ControlLogix/CompactLogix",
    ],
    read_options={
        "address": "tag 名字符串 (如 alpha[0]); 支持单维下标",
        "count": "元素个数 (数组 tag)",
    },
)
