"""Modbus 协议元数据: TCP 与 RTU-over-TCP 两个传输变体。"""

from plctap.protocols.base import ProtocolMeta

# 汇川/台达/信捷/永宏等国产 PLC 均原生支持 Modbus TCP/RTU (兼容性声明,
# 未经专有协议栈验证 —— 帧级行为以 Modbus 规范为准)
_CN_VENDORS = ["汇川 Inovance", "台达 Delta", "信捷 Xinje", "永宏 FATEK"]

META = ProtocolMeta(
    name="modbus",
    default_port=502,
    port_hints=[502, 1502, 5020, 15020],
    addressing_model="register",
    summary="Modbus TCP (最通用的工业协议, 支持品牌最广)",
    data_types=["uint16", "int16", "float32"],
    vendor_hints=[
        "Siemens",
        "Schneider",
        "Wago",
        "通用网关",
        "Modbus TCP 从站",
        *_CN_VENDORS,
    ],
    read_options={'function_code': '3=保持寄存器 (默认), 4=输入寄存器'},
)

META_RTU = ProtocolMeta(
    name="modbus_rtu",
    default_port=502,
    port_hints=[502, 5021, 8899, 5020],
    addressing_model="register",
    summary=(
        "Modbus RTU over TCP (串口服务器/网关 RTU 模式: 线帧=addr+PDU+CRC16, "
        "无 MBAP; Moxa MGate/NPort 类设备常见)"
    ),
    data_types=["uint16", "int16", "float32"],
    vendor_hints=[
        "Moxa MGate/NPort",
        "映翰通 InHand",
        "研华 ADAM",
        "串口网关 RTU 模式",
        *_CN_VENDORS,
    ],
    read_options={'function_code': '3=保持寄存器 (默认), 4=输入寄存器'},
)
