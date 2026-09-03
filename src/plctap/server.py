"""FastMCP 应用入口: 工具注册 + 条件注册闸门 (ARCHITECTURE.md 第 1 节)。

MCP 协议层永远是 Server; 工业协议层只做 Client/主站 (第 9 节)。
工具命名与描述面向 Agent 的自发现: 描述里写清"何时用/返回什么",
不做自然语言解析 (HANDOFF 红线 3)。
"""

from __future__ import annotations

from fastmcp import FastMCP

from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import (
    ByteOrder,
    CheckResult,
    ParseResult,
    ProbeResult,
    ReadResult,
    Target,
)
from plctap.protocols.base import adapter_for, known_protocols
from plctap.protocols.modbus.adapter import ModbusAdapter  # noqa: F401  # 注册副作用
from plctap.safety import AuditLog

_INSTRUCTIONS = (
    "plctap 是 Agent 的 PLC 驱动层 (Modbus TCP / FINS / MELSEC)。\n"
    "典型流程: probe_device 确认连通性与故障层 -> plc_read 取数 -> "
    "parse_frame/validate_frame 做报文级深挖。\n"
    "所有工具无状态: 每次调用都带 host/port, 不需要维护会话。"
)


def create_app(config: PlctapConfig | None = None) -> FastMCP:
    config = config or PlctapConfig.from_env()
    mcp = FastMCP("plctap", instructions=_INSTRUCTIONS)
    pool = ConnectionPool(
        idle_timeout_sec=config.idle_timeout_sec,
        max_per_target=config.pool_max_per_target,
    )
    audit = AuditLog(config.audit_log)

    def _adapter(protocol: str):
        return adapter_for(protocol)(pool, config)

    # ------------------------------------------------------------ 能力自述

    @mcp.tool
    def list_protocols() -> dict:
        """列出本 server 支持的工业协议及其能力 (连接探测/读取/写/原始帧)。

        Agent 不确定协议名时先调用本工具; 已支持协议的适配器通过注册表
        自动出现, 无需改 server 代码。
        """
        return {
            "protocols": {
                name: {
                    "probe": True,
                    "read": True,
                    "write": config.allow_write,  # 写能力随闸门而变 (D5)
                    "send_raw": config.allow_write,
                }
                for name in known_protocols()
            },
            "allow_write": config.allow_write,
        }

    # ------------------------------------------------------------ 连接层

    @mcp.tool
    async def probe_device(
        protocol: str,
        host: str,
        port: int,
        unit: int = 1,
    ) -> ProbeResult:
        """测试能否连上 PLC 并通信, 失败时给出层级归因。

        返回 reachable; 失败时 failure_class 取:
        - connection_refused: 端口没人监听/网络不可达 (查网络与端口)
        - timeout: 连接超时 (查网络路由/防火墙)
        - connected_but_no_reply: TCP 通了但设备不回话 (查协议配置)
        - exception_response: 设备回异常码 (查 unit/寄存器配置, 带 exception_code)
        典型用法: 设备"读不到数据"时先调本工具分层定位, 再决定下一步。
        """
        return await _adapter(protocol).probe(
            Target(protocol=protocol, host=host, port=port, unit=unit)
        )

    @mcp.tool
    async def plc_read(
        protocol: str,
        host: str,
        port: int,
        address: int,
        count: int = 1,
        unit: int = 1,
        datatype: str | None = None,
        byteorder: ByteOrder = "big",
        function_code: int = 3,
        timeout_ms: int | None = None,
    ) -> ReadResult:
        """从 PLC 读取数据区并按数据类型解释。

        Modbus: address 为 0 基寄存器地址 (口语"40001"对应 address=0);
        count 为寄存器个数 (fc3=保持寄存器, fc4=输入寄存器);
        datatype 取 uint16/int16/float32, None 返回原始 16 位值;
        byteorder 仅影响 float32 的寄存器对组合顺序 (big=ABCD, little=DCBA)。
        返回 ReadResult: raw_registers 原始值 + interpreted 解释值 +
        request_frame 请求帧 hex (便于核对通信)。
        """
        return await _adapter(protocol).read(
            Target(protocol=protocol, host=host, port=port, unit=unit),
            address=address,
            count=count,
            datatype=datatype,
            byteorder=byteorder,
            timeout_ms=timeout_ms,
            function_code=function_code,
        )

    # ------------------------------------------------------------ 诊断层

    @mcp.tool
    async def parse_frame(
        protocol: str, frame_hex: str, direction: str = "auto"
    ) -> ParseResult:
        """把一帧报文 hex 逐字段结构化解析 (不需要连接设备)。

        每个字段带 byte_offset 与 raw_hex 证据; 支持正常请求/响应与异常
        响应帧; 畸形帧不抛错, 而是尽量解析并在 errors 里说明哪里坏 ——
        "解析失败的方式"本身是诊断证据。
        direction: "auto" 按帧结构判别 (异常帧/非 12 字节按响应, 12 字节
        按请求; fc05/06 的响应与请求完全相同, 任一解释结果一致), 也可
        显式传 "req" / "resp"。
        """
        if direction not in ("auto", "req", "resp"):
            raise ValueError(f"direction must be 'auto'|'req'|'resp', got {direction!r}")
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        if protocol == "modbus":
            return _parse_modbus(frame, direction)  # type: ignore[arg-type]
        raise ValueError(f"parse_frame not implemented for {protocol!r} yet")

    @mcp.tool
    async def validate_frame(
        protocol: str, frame_hex: str, direction: str = "resp"
    ) -> list[CheckResult]:
        """对一帧报文跑规范校验清单, 逐项 pass/fail (不需要连接设备)。

        Modbus TCP 检查项: MBAP 长度一致性、协议号、功能码合法性、
        unit 范围、PDU 长度自洽、数量/地址边界、异常码合法性。
        注意: Modbus TCP 无 CRC (RTU 才有)。direction 取 req 或 resp。
        """
        if direction not in ("req", "resp"):
            raise ValueError(f"direction must be 'req' or 'resp', got {direction!r}")
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        if protocol == "modbus":
            from plctap.protocols.modbus import codec

            return codec.validate_frame(frame, direction)  # type: ignore[arg-type]
        raise ValueError(f"validate_frame not implemented for {protocol!r} yet")

    # ------------------------------------------------------------ 执行层 (闸门)

    if config.allow_write:
        _register_write_tools(mcp, pool, config, audit)
    # allow_write=False 时写类工具根本不注册, Agent 不可见 (D5)

    return mcp


def _parse_modbus(frame: bytes, direction: str) -> ParseResult:
    """方向判别后调用对应 codec 纯函数。

    auto 规则: ① 功能码 |0x80 只在响应方向出现 -> resp;
    ② fc01-06 请求帧恒为 12 字节 -> req (fc05/06 响应是请求的逐字节回显,
    两种解释字段一致, 优先 req 无信息损失);
    ③ 其余按响应解析 (诊断场景抓到的多为设备响应)。
    """
    from plctap.protocols.modbus import codec

    if direction == "req":
        return codec.parse_request(frame)
    if direction == "resp":
        return codec.parse_response(frame)
    # auto
    if len(frame) >= 8 and frame[7] & codec.EXCEPTION_FLAG:
        return codec.parse_response(frame)
    if len(frame) == 12 and len(frame) >= 8 and frame[7] in codec.KNOWN_FCS:
        return codec.parse_request(frame)
    return codec.parse_response(frame)


def _register_write_tools(
    mcp: FastMCP,
    pool: ConnectionPool,
    config: PlctapConfig,
    audit: AuditLog,
) -> None:
    """写类工具 (M3): 仅 allow_write=true 时注册, 每次调用写审计日志。"""

    @mcp.tool
    async def plc_write(
        protocol: str,
        host: str,
        port: int,
        address: int,
        value: int,
        unit: int = 1,
    ) -> dict:
        """写单个线圈 (fc05) 或寄存器 (fc06)。危险操作: 需要用户明确授权。"""
        audit.record(
            tool="plc_write",
            target=f"{protocol}://{host}:{port} unit={unit}",
            frame_hex=f"addr={address} value={value}",
        )
        adapter = adapter_for(protocol)(pool, config)
        return await adapter.write(
            Target(protocol=protocol, host=host, port=port, unit=unit),
            address,
            [value],
        )


def main() -> None:
    """console script 入口: 默认 stdio transport。"""
    app = create_app()
    app.run()


if __name__ == "__main__":
    main()
