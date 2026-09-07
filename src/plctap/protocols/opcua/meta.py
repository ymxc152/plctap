"""OPC UA (IEC 62541) 协议元数据 (v0.6)。

会话式协议, 定位是"连接能力"而非"帧级诊断" —— addressing_model 用
node_id (NodeId 字符串), 与其余端点的整数地址/tag 名并列第三种形态。
"""

from plctap.protocols.base import ProtocolMeta

META = ProtocolMeta(
    name="opcua",
    default_port=4840,
    port_hints=[4840, 4841],
    addressing_model="node_id",
    summary=(
        "OPC UA (IEC 62541, 新建项目事实标准; 4840; 会话协议, 连接级诊断: "
        "SecurityPolicy None + node id 读 + 地址空间 browse, 不做帧级解析)"
    ),
    # 返回值为 asyncua 原生类型 (标量或数组), data_types 列出常见形态
    data_types=["bool", "double", "float", "int32", "uint32", "int64", "string", "datetime", "array"],
    vendor_hints=[
        "OPC Foundation 规范实现",
        "Siemens S7-1200/1500 (内建 OPC UA server)",
        "KEPServerEX / Ignition",
        "Beckhoff TwinCAT",
    ],
    read_options={
        "address": "NodeId 字符串 (如 ns=2;i=5 或 ns=2;s=Demo.Double)",
        "count": "数组节点返回元素上限 (0=全部); 标量节点忽略",
    },
)
