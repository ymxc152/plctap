"""plctap — Agent-PLC MCP Server。

让 Claude / Codex / Cursor 直接连接、读写、诊断 Modbus TCP / FINS / MELSEC PLC。
"""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("plctap")
except PackageNotFoundError:  # 源码目录直接 import (未安装) 的兜底
    __version__ = "0+unknown"
