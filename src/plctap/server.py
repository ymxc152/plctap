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
    DiagnosticReport,
    ParseResult,
    ProbeResult,
    ReadResult,
    Target,
)
from plctap.protocols.base import adapter_for, known_protocols
from plctap.protocols.fins.adapter import FinsAdapter  # noqa: F401  # 注册副作用
from plctap.protocols.melsec.adapter import MelsecAdapter  # noqa: F401  # 注册副作用
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
                    "send_raw": False,  # send_frame 工具 M3 注册前恒为 False (与实际一致)
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

        reachable = 传输层可达 (TCP 已建立; 设备回异常响应也算在线)。
        failure_class 取:
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
        area: str = "DM",
        device: str = "D",
        timeout_ms: int | None = None,
    ) -> ReadResult:
        """从 PLC 读取数据区并按数据类型解释。

        Modbus: address 为 0 基寄存器地址 (口语"40001"对应 address=0);
        count 为寄存器个数 (fc3=保持寄存器, fc4=输入寄存器)。
        FINS: area 取 CIO/W/H/A/DM/EM, address 为字地址, count 为字数。
        MELSEC: device 取 D/R/W (字软元件) 或 X/Y/B/M (位软元件, 每字
        16 点), address 为起始编号, count 为点数。
        datatype 取 uint16/int16/float32, None 返回原始 16 位值;
        byteorder 仅影响 float32 的寄存器对组合顺序 (big=ABCD/高字在前,
        little=DCBA/低字在前; MELSEC 线上原生为小端)。
        返回 ReadResult: raw_registers 原始值 + interpreted 解释值 +
        request_frame 请求帧 hex (便于核对通信)。
        """
        target = Target(protocol=protocol, host=host, port=port, unit=unit)
        # 协议特有参数只传给对应适配器 (function_code/area/device 语义不同)
        kwargs: dict[str, object] = {
            "address": address,
            "count": count,
            "datatype": datatype,
            "byteorder": byteorder,
            "timeout_ms": timeout_ms,
        }
        if protocol == "modbus":
            kwargs["function_code"] = function_code
        elif protocol == "fins":
            kwargs["area"] = area
        elif protocol == "melsec":
            kwargs["device"] = device
        return await _adapter(protocol).read(target, **kwargs)  # type: ignore[arg-type]

    # ------------------------------------------------------------ 诊断层

    @mcp.tool
    async def diagnose(
        protocol: str,
        frame_hex: str | None = None,
        log_snippet: str | None = None,
        host: str | None = None,
        port: int | None = None,
        unit: int = 1,
    ) -> DiagnosticReport:
        """综合观测给出结构化的故障候选结论 (确定性规则, 不编故事)。

        三种证据可任意组合 (至少给一种):
        - frame_hex: 一帧报文 hex (解析 + 校验 + 规则匹配)
        - log_snippet: 通信日志文本, 自动提取其中的 hex 帧逐帧解析
        - host + port: 连上设备做一次探测, 把探测归因纳入推理
        返回 DiagnosticReport: candidates 按 confidence 降序, 每条含
        symptom/root_cause/evidence(证据链)/suggested_action/next_tools;
        evidence 与 observations 保留原始观测供复核。空 candidates =
        知识库未覆盖, 不硬凑结论。
        """
        if not any((frame_hex, log_snippet, host)):
            raise ValueError("provide at least one of frame_hex / log_snippet / host+port")
        probe_result = None
        if host:
            if not port:
                raise ValueError("host given without port; port is required for probing")
            target = Target(protocol=protocol, host=host, port=port, unit=unit)
            probe_result = await _adapter(protocol).probe(target)
        frames_hex = [frame_hex] if frame_hex else None
        from plctap.diag.engine import diagnose as run_diagnosis

        return run_diagnosis(protocol, frames_hex=frames_hex, log_snippet=log_snippet, probe_result=probe_result)

    @mcp.tool
    async def parse_frame(
        protocol: str, frame_hex: str, direction: str = "auto"
    ) -> ParseResult:
        """把一帧报文 hex 逐字段结构化解析 (不需要连接设备)。

        每个字段带 byte_offset 与 raw_hex 证据; 支持正常请求/响应与异常
        响应帧; 畸形帧不抛错, 而是尽量解析并在 errors 里说明哪里坏 ——
        "解析失败的方式"本身是诊断证据。
        direction: "auto" 按帧结构判别, 也可显式传 "req" / "resp"。
        - modbus: 异常帧/非 12 字节按响应, 12 字节按请求 (fc05/06 的响应
          与请求逐字节相同, 任一解释一致)
        - fins: TCP 命令 0x00 按请求 / 0x01、0x02 按响应; 0x04 按 FINS
          ICF bit6 判别 (响应置位)
        - melsec: 数据首字为已知命令 (0x0401) 按请求, 否则按响应
          (结束代码非 0 的异常响应也能正确归向)
        """
        if direction not in ("auto", "req", "resp"):
            raise ValueError(f"direction must be 'auto'|'req'|'resp', got {direction!r}")
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        if protocol in ("modbus", "fins", "melsec"):
            from plctap.protocols.auto import parse_auto

            return parse_auto(protocol, frame)
        raise ValueError(f"parse_frame not implemented for {protocol!r} yet")

    @mcp.tool
    async def validate_frame(
        protocol: str, frame_hex: str, direction: str = "resp"
    ) -> list[CheckResult]:
        """对一帧报文跑规范校验清单, 逐项 pass/fail (不需要连接设备)。

        Modbus TCP: MBAP 长度一致性、协议号、功能码、unit 范围、PDU
        自洽、数量/地址边界、异常码 (Modbus TCP 无 CRC, RTU 才有)。
        FINS/TCP: magic、TCP 长度自洽、TCP 命令合法、error 字段、
        FINS 端结码、载荷完整性。
        MELSEC 3E: 副头部、数据长度自洽、命令/软元件代码、结束代码。
        direction 取 req 或 resp。
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
        if protocol == "fins":
            from plctap.protocols.fins import codec

            return codec.validate_frame(frame, direction)  # type: ignore[arg-type]
        if protocol == "melsec":
            from plctap.protocols.melsec import codec

            return codec.validate_frame(frame, direction)  # type: ignore[arg-type]
        raise ValueError(f"validate_frame not implemented for {protocol!r} yet")

    # ------------------------------------------------------------ 执行层 (闸门)

    if config.allow_write:
        _register_write_tools(mcp, pool, config, audit)
    # allow_write=False 时写类工具根本不注册, Agent 不可见 (D5)

    return mcp


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
        point_type: str = "register",
        timeout_ms: int | None = None,
    ) -> dict:
        """写单个数据点 (危险操作: 需要用户明确授权)。

        point_type: "register"=fc06 写保持寄存器 / "coil"=fc05 写线圈;
        value 对线圈只接受 0/1 (线上为 0x0000/0xFF00)。
        返回 {"request_frame", "response_frame", "elapsed_ms"};
        完整请求帧在发送前写入审计日志 (D5: 失败也留痕)。
        """
        if point_type not in ("coil", "register"):
            raise ValueError(f"point_type must be 'coil'|'register', got {point_type!r}")
        adapter = adapter_for(protocol)(pool, config)
        return await adapter.write(
            Target(protocol=protocol, host=host, port=port, unit=unit),
            address,
            [value],
            on_frame=lambda hexstr: audit.record(
                tool="plc_write",
                target=f"{protocol}://{host}:{port} unit={unit}",
                frame_hex=hexstr,
            ),
            point_type=point_type,
            timeout_ms=timeout_ms,
        )


def main() -> None:
    """console script 入口: 默认 stdio transport。"""
    app = create_app()
    app.run(show_banner=False)


if __name__ == "__main__":
    main()

