"""Modbus TCP 协议适配器 (M1)。

职责边界: 本模块只做网络 I/O 与会话管理 (D3 纯 asyncio); 帧的构造/
解析/校验全部调用 codec 纯函数 (D2)。
"""
