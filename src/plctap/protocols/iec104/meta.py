"""IEC 60870-5-104 协议元数据。"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="iec104",
    default_port=2404,
    port_hints=[2404, 2405],
    addressing_model="ioa",
    summary=(
        "IEC 60870-5-104 (电力远动/SCADA 主-从通信, 2404 端口; "
        "I/S/U 三种帧型, 遥信遥测遥脉)"
    ),
    data_types=["uint16", "int16", "float32"],
    vendor_hints=[
        "电力远动/调度",
        "SCADA 主站",
        "南瑞",
        "许继",
        "积成电子",
        "变电站终端 RTU",
    ],
    read_options={
        "ca": "公共地址 (ASDU CA, 默认 1)",
        "qoi": "总召 QOI (默认 20 站总召)",
        "count": "读连续 IOA 点数 (M_ME_NC 每点占 2 个 16 位字)",
    },
)
