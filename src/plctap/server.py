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
    PcapFlow,
    ParseResult,
    ProbeResult,
    RawExchange,
    ReadResult,
    Target,
)
from plctap.protocols.base import ProtocolAdapter, adapter_for, known_protocols
from plctap.protocols.fins.adapter import FinsAdapter  # noqa: F401  # 注册副作用
from plctap.protocols.melsec.adapter import MelsecAdapter  # noqa: F401  # 注册副作用
from plctap.protocols.s7.adapter import S7Adapter  # noqa: F401  # 注册副作用
from plctap.protocols.modbus.adapter import ModbusAdapter  # noqa: F401  # 注册副作用
from plctap.protocols.iec104.adapter import Iec104Adapter  # noqa: F401  # 注册副作用
from plctap.protocols.enip.adapter import EnipAdapter  # noqa: F401  # 注册副作用
from plctap.protocols.detect import DetectResult, DeviceDetector
from plctap.listener import ListenerRegistry
from plctap.proxy import ProxyRegistry
from plctap.safety import AuditLog

_INSTRUCTIONS = (
    "plctap 是 Agent 的 PLC 驱动层 (Modbus TCP / FINS / MELSEC)。\n"
    "典型流程: probe_device 确认连通性与故障层 -> plc_read 取数 -> "
    "parse_frame/validate_frame 做报文级深挖。\n"
    "报文证据三来源: frame_hex / log_snippet / pcap 文件 (parse_pcap)。\n"
    "设备只能当 client 时: start_listener 起钓鱼监听收帧再分析。\n"
    "所有工具无状态: 每次调用都带 host/port, 不需要维护会话 (listener 是例外,\n"
    "它有 start/stop/frames 生命周期)。"
)


def _validate_address(protocol: str, address: int | str) -> None:
    """服务层地址类型闸: enip 用 tag 名字符串, 其余协议用整数地址。

    enip 适配器只接受字符串 tag (如 "alpha[0]"), 而 MCP schema 此前把
    address 钉死为 int, 导致 enip 端点经工具层无法调用 —— 签名放宽为
    int | str 后在此按协议给出明确报错, 而不是漏进适配器深处炸 TypeError。
    """
    if protocol == "enip":
        if not isinstance(address, str):
            raise ValueError(
                'enip 的 address 必须是 tag 名字符串 (如 "alpha[0]"); '
                "整数地址仅用于其余协议"
            )
    elif not isinstance(address, int) or isinstance(address, bool):
        raise ValueError(
            f"{protocol} 的 address 必须是整数地址; tag 名字符串仅 enip 支持"
        )


def create_app(config: PlctapConfig | None = None) -> FastMCP:
    config = config or PlctapConfig.from_env()
    mcp = FastMCP("plctap", instructions=_INSTRUCTIONS)
    pool = ConnectionPool(
        idle_timeout_sec=config.idle_timeout_sec,
        max_per_target=config.pool_max_per_target,
    )
    audit = AuditLog(config.audit_log)
    listeners = ListenerRegistry()
    proxies = ProxyRegistry()
    detector = DeviceDetector(pool, config)

    def _adapter(protocol: str):
        return adapter_for(protocol)(pool, config)

    def _norm_frame_protocol(protocol: str) -> str:
        """modbus_rtu 与 modbus 帧级同轨 (RTU 双轨判别/知识库共用), 帧级工具归一。"""
        return "modbus" if protocol == "modbus_rtu" else protocol

    # ------------------------------------------------------------ 能力自述

    @mcp.tool
    def list_protocols() -> dict:
        """列出本 server 支持的工业协议及其能力。

        返回每个协议的端口提示、地址模型、数据类型和品牌线索,
        Agent 可据此推断 "这个设备该用什么协议" 而无需问用户。
        不确定协议名时先调用本工具。
        不确定协议/端口时先调用 detect_device。
        """
        protocols = {}
        for name in known_protocols():
            cls = adapter_for(name)
            meta = cls.meta
            # 写能力 = 闸门开启 且 适配器真正覆写了 write/send_raw
            # (fins/melsec 未实现 write, 不能因闸门开启就向 Agent 谎报)
            entry: dict = {
                "probe": True,
                "read": True,
                "write": config.allow_write and cls.write is not ProtocolAdapter.write,
                "send_raw": config.allow_write and cls.send_raw is not ProtocolAdapter.send_raw,
            }
            if meta:
                entry.update({
                    "default_port": meta.default_port,
                    "port_hints": meta.port_hints,
                    "addressing_model": meta.addressing_model,
                    "summary": meta.summary,
                    "data_types": meta.data_types,
                    "vendor_hints": meta.vendor_hints,
                    "read_options": meta.read_options,
                })
            protocols[name] = entry
        return {
            "protocols": protocols,
            "allow_write": config.allow_write,
            "hint": "根据 vendor_hints 和 port_hints 匹配设备; 无法确定时向用户确认品牌",
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
        address: int | str,
        count: int = 1,
        unit: int = 1,
        datatype: str | None = None,
        byteorder: ByteOrder = "big",
        timeout_ms: int | None = None,
        options: dict | None = None,
    ) -> ReadResult:
        """从 PLC 读取数据区并按数据类型解释。

        address/count 为通用地址与数量, 语义由协议决定:
        - Modbus: address 为 0 基寄存器地址, count 为寄存器个数
        - FINS: address 为字地址, count 为字数
        - MELSEC: address 为起始编号, count 为点数 (位软元件按 16 点/字)
        - S7: address 为字节地址, count 为**字节数** (count=4 + uint16 → 2 个值)
        - EtherNet/IP: address 为 tag 名字符串 (如 "alpha[0]"), count 为元素个数

        datatype 取 uint16/int16/float32, None 返回原始 16 位值 + 所有常见数据类型的多解释 (interpretations 字段), 便于 Agent 识别正确的数据类型。
        byteorder 仅影响 float32 寄存器对顺序 (big=ABCD, little=DCBA)。

        options: 协议特有参数, 由各协议 adapter 自行定义与校验。
        用 list_protocols 查看每个协议的 read_options 说明。
        """
        _validate_address(protocol, address)
        target = Target(protocol=protocol, host=host, port=port, unit=unit)
        result = await _adapter(protocol).read(
            target,
            address=address,
            count=count,
            datatype=datatype,
            byteorder=byteorder,
            timeout_ms=timeout_ms,
            **(options or {}),
        )
        if datatype is None and result.raw_registers:
            from plctap.protocols.common import interpret_all
            result.interpretations = interpret_all(result.raw_registers)
        return result

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

        # modbus_rtu 帧与 modbus 同轨 (RTU 双轨判别), 知识库共用
        return run_diagnosis(_norm_frame_protocol(protocol), frames_hex=frames_hex, log_snippet=log_snippet, probe_result=probe_result)

    @mcp.tool
    async def parse_frame(
        protocol: str, frame_hex: str, direction: str = "auto",
        frame_format: str = "3e_binary",
    ) -> ParseResult:
        """把一帧报文 hex 逐字段结构化解析 (不需要连接设备)。

        每个字段带 byte_offset 与 raw_hex 证据; 支持正常请求/响应与异常
        响应帧; 畸形帧不抛错, 而是尽量解析并在 errors 里说明哪里坏 ——
        "解析失败的方式"本身是诊断证据。
        direction: "auto" 按帧结构判别, 也可显式传 "req" / "resp"。
        frame_format (仅 melsec): "3e_binary" / "3e_ascii" / "4e_binary" / "4e_ascii"。
        - modbus: 异常帧/非 12 字节按响应, 12 字节按请求 (fc05/06 的响应
          与请求逐字节相同, 任一解释一致)
        - fins: TCP 命令 0x00 按请求 / 0x01、0x02 按响应; 0x04 按 FINS
          ICF bit6 判别 (响应置位)
        - melsec: 副头部 50 00/54 00 按请求, D0 00/D4 00 按响应
          (ASCII 帧 "5000"/"5400"/"D000"/"D400" 同理)
        - s7: rosctr=0x01 (Job) 按请求, 0x03 (Ack_Data) 按响应; 显式传
          direction 时按传入值
        """
        if direction not in ("auto", "req", "resp"):
            raise ValueError(f"direction must be 'auto'|'req'|'resp', got {direction!r}")
        protocol = _norm_frame_protocol(protocol)
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        if protocol == "melsec":
            import struct as _struct
            from plctap.protocols.melsec import codec as mc

            if direction == "auto":
                # Auto-detect: 副头部 50 00/54 00 = 请求, D0 00/D4 00 = 响应 (大端)
                if len(frame) >= 2:
                    (sub,) = _struct.unpack_from(">H", frame, 0)
                    if sub == 0x5400:
                        frame_format = "4e_binary"
                    elif sub == 0xD000:
                        return mc.parse_response_fmt(frame, frame_format="3e_binary")
                    elif sub == 0xD400:
                        return mc.parse_response_fmt(frame, frame_format="4e_binary")
                    elif len(frame) >= 4:
                        try:
                            ascii_sub = frame[0:4].decode("ascii")
                            if ascii_sub == "5400":
                                frame_format = "4e_ascii"
                            elif ascii_sub == "5000":
                                frame_format = "3e_ascii"
                            elif ascii_sub == "D000":
                                return mc.parse_response_fmt(frame, frame_format="3e_ascii")
                            elif ascii_sub == "D400":
                                return mc.parse_response_fmt(frame, frame_format="4e_ascii")
                        except (UnicodeDecodeError, ValueError):
                            pass
                return mc.parse_request_fmt(frame, frame_format)
            if direction == "req":
                return mc.parse_request_fmt(frame, frame_format)
            return mc.parse_response_fmt(frame, frame_format=frame_format)
        if protocol == "s7":
            from plctap.protocols.s7 import codec as sc

            if direction == "auto":
                rosctr = frame[8] if len(frame) > 8 else -1
                direction = "req" if rosctr == sc.ROSCR_JOB else "resp"
            if direction == "req":
                return sc.parse_request(frame)
            return sc.parse_read_response(frame)
        if protocol in ("modbus", "fins", "iec104", "enip"):
            from plctap.protocols.auto import parse_auto

            return parse_auto(protocol, frame)
        raise ValueError(f"parse_frame not implemented for {protocol!r} yet")

    @mcp.tool
    async def validate_frame(
        protocol: str, frame_hex: str, direction: str = "resp",
        frame_format: str = "3e_binary",
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
        protocol = _norm_frame_protocol(protocol)
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        import importlib

        try:
            codec_mod = importlib.import_module(
                f"plctap.protocols.{protocol}.codec"
            )
        except ModuleNotFoundError:
            raise ValueError(
                f"validate_frame not implemented for {protocol!r}"
            ) from None
        if protocol == "melsec":
            return codec_mod.validate_frame_fmt(frame, direction, frame_format=frame_format)
        return codec_mod.validate_frame(frame, direction)

    # ------------------------------------------------------------ 报文证据: pcap

    @mcp.tool
    async def parse_pcap(path: str, protocol: str | None = None) -> list[PcapFlow]:
        """解析 Wireshark 导出 pcap: 按 TCP 流聚合载荷 -> 按协议切帧 -> 逐帧 parse_auto。

        每个流返回完整帧序列 (带结构化解析) 与尾部半帧 (partial, 截断也是
        诊断信息)。protocol 缺省时按"完整帧数最多的协议"自动判别。
        需要可选依赖 scapy (uv sync --extra eval)。大批量帧场景比逐条
        frame_hex 高效得多。
        输出受 64KB token 预算约束: 超出时按流序/帧序装帧并截断, 末尾追加
        一条 flow 以 "truncated:" 开头的 sentinel 流 (frames 为空, 带
        total/shown 计数)。需要其余帧时用 protocol= 过滤或拆分 pcap 再解析。
        """
        from plctap import pcap

        return pcap.parse_pcap_file(path, protocol)

    # ------------------------------------------------------------ 钓鱼模式监听

    @mcp.tool
    async def start_listener(
        protocol: str,
        host: str = "0.0.0.0",
        port: int = 0,
        mode: str = "record_only",
        idle_timeout_sec: int = 120,
        faults: list[str] | None = None,
    ) -> dict:
        """起钓鱼模式监听: 待测设备只能当 client 时, 立假 server 钓出它的帧行为。

        mode 三档: record_only=只收帧不回复 (纯被动) / respond_normal=对读类
        请求回最小"正常响应" (数据恒 0, 目的只是让设备继续吐帧, 非通用模拟器)
        / inject_errors=正常回帧但按 faults 列表轮转注入确定性故障 (评测语料
        生产 + 诊断引擎回归)。
        faults (仅 inject_errors): modbus 可选 exception/bad_length/truncate,
        fins/melsec 可选 end_code/bad_length, 全协议通用 garbage。
        收下的帧用 get_listener_frames 取, 再喂 parse_frame/diagnose。
        port=0 由系统分配, 返回实际端口。建议收满样本后 stop_listener,
        并提醒用户恢复设备原配置 (BUILD.md Skill 节)。
        """
        return await listeners.start(protocol, host, port, mode, idle_timeout_sec, faults)

    @mcp.tool
    async def stop_listener(port: int) -> dict:
        """停掉指定端口的监听, 返回收/发帧统计。"""
        return await listeners.stop(port)

    @mcp.tool
    async def get_listener_frames(port: int, limit: int = 100) -> list[dict]:
        """取监听收下的帧 (direction/peer/frame_hex), 供 parse_frame/diagnose 分析。"""
        return listeners.frames(port, limit)

    # ------------------------------------------------------------ 透明代理

    @mcp.tool
    async def start_proxy(
        protocol: str,
        target_host: str,
        target_port: int,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        idle_timeout_sec: int = 120,
    ) -> dict:
        """起透明代理: 上位机 → 代理 → 真实 PLC, 透传同时按协议分帧录制双向帧。

        现场联调时把上位机目标地址改成本代理, 无需 Wireshark 即可拿到全部
        交互帧 (get_proxy_frames), 再喂 parse_frame/diagnose 做在线分析。
        protocol 当前支持 modbus/fins/melsec (S7 TPKT 分帧暂不支持);
        listen_port=0 由系统分配。代理是诊断设施: 只透传与录制, 不改写帧。
        """
        return await proxies.start(
            protocol, listen_host, listen_port, target_host, target_port, idle_timeout_sec
        )

    @mcp.tool
    async def stop_proxy(port: int) -> dict:
        """停掉指定端口的代理, 返回录制统计 (c2s/s2c 帧数)。"""
        return await proxies.stop(port)

    @mcp.tool
    async def get_proxy_frames(port: int, limit: int = 100) -> list[dict]:
        """取代理录制的双向透传帧 (direction: c2s=上位机→PLC, s2c=PLC→上位机)。"""
        return proxies.frames(port, limit)

    # ------------------------------------------------------------ 设备自动识别

    @mcp.tool
    async def detect_device(
        host: str,
        ports: list[int] | None = None,
        timeout_ms: int | None = None,
        deep: bool = True,
    ) -> DetectResult:
        """设备自动识别: 给定 host 自动扫端口并判定协议 (v0.4, 全程只读)。

        流程: 并发扫描候选端口 (缺省 102/502/2000/44818/5007/6000/9600/9601,
        单端口连接预算 0.5s) -> 开放端口并发跑四协议 probe 指纹 (单协议
        预算 timeout_ms/1000, 缺省 0.8s) -> high 候选按协议做一次最小读
        验证 (deep=True 缺省; 成功升级 verified, 失败留痕保持 high;
        deep=False 跳过验证读)。
        只读保证: 全程只发握手帧 + 最小读帧, 不写任何数据; 且识别 ≠ 可访问
        —— 例如 S7 PUT/GET 被关闭时识别照样成功, 读 DB 仍可能失败。
        返回 DetectResult: candidates 按置信度降序 (同级先验匹配端口优先,
        next_step 可直接作为 plc_read 调用), unknown_services 为开放但
        四协议都不认识的端口 (可用 start_listener 钓帧分析)。
        """
        return await detector.detect(host, ports=ports, timeout_ms=timeout_ms, deep=deep)

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
        address: int | str,
        value: int,
        unit: int = 1,
        point_type: str = "register",
        timeout_ms: int | None = None,
        options: dict | None = None,
    ) -> dict:
        """写数据点 (危险操作: 需要用户明确授权)。

        Modbus:
          point_type="register" 默认 fc16 (Write Multiple Registers),
          兼容绝大多数模拟器/PLC (IoTClient 实测 fc06 不被支持)。
          options.function_code=6 可切换 fc06 (Write Single Register)。
          options.values=[v1,v2,...] 批量写多个寄存器 (fc16, 最多 123 个)。
          point_type="coil" 使用 fc05 (Write Single Coil)。

        S7:
          values 为 16 位字 (每个值占 2 字节, 大端), 逐字写入
          area/db_number/address 起的连续区域。

        FINS:
          options.area 指定存储区 (CIO/W/H/A/DM/EM, 默认 DM);
          values 为 16 位字 (大端), 0102 存储区写。

        MELSEC:
          options.device 指定软元件 (默认 D), options.frame_format
          支持 3e/4E × binary/ascii; 1401 批量写字, 位软元件按打包字写
          (每字 16 点)。

        返回 {"request_frame", "response_frame", "elapsed_ms"}。
        完整请求帧在发送前写入审计日志 (D5: 失败也留痕)。

        EtherNet/IP: address 为 tag 名字符串 (如 "alpha[0]"); values
        (options.values 或 [value]) 为 16 位字序列, 整数默认 DINT,
        浮点需显式 options.type="REAL"。
        """
        _validate_address(protocol, address)
        opts = options or {}
        if point_type not in ("coil", "register"):
            raise ValueError(f"point_type must be 'coil'|'register', got {point_type!r}")
        values = opts.pop("values", None) or [value]
        function_code = opts.pop("function_code", None)
        adapter_cls = adapter_for(protocol)
        adapter = adapter_cls(pool, config)
        if adapter_cls.write is ProtocolAdapter.write:  # 类级比较 (实例 bound method 无稳定身份)
            supported = ", ".join(
                n for n in known_protocols()
                if adapter_for(n).write is not ProtocolAdapter.write
            )
            raise ValueError(
                f"{protocol} write 未实现 (plc_write 当前支持 {supported}); 详见 list_protocols"
            )
        # _function_code 仅 Modbus 语义 (fc05/06/16); 其他协议不传, 避免吞掉
        # 基类的 "write not implemented" 明确报错
        extra = {"_function_code": function_code} if protocol in ("modbus", "modbus_rtu") else {}
        return await adapter.write(
            Target(protocol=protocol, host=host, port=port, unit=unit),
            address,
            values,
            on_frame=lambda hexstr: audit.record(
                tool="plc_write",
                target=f"{protocol}://{host}:{port} unit={unit}",
                frame_hex=hexstr,
            ),
            point_type=point_type,
            timeout_ms=timeout_ms,
            **extra,
            **opts,
        )

    @mcp.tool
    async def send_frame(
        protocol: str,
        host: str,
        port: int,
        frame_hex: str,
        unit: int = 1,
        timeout_ms: int | None = None,
    ) -> RawExchange:
        """发送任意原始帧并等待一帧响应 (危险: 直接与真实设备交互)。

        完整帧在发送前写入审计日志 (D5: 失败也留痕); 与 plc_write 同受
        allow_write 闸门控制。用于协议调试/故障注入复现; 常规读写请用
        plc_read / plc_write, 不要用原始帧。
        """
        try:
            bytes.fromhex(frame_hex)
        except ValueError as e:
            raise ValueError(f"frame_hex is not valid hex: {e}") from e
        adapter = adapter_for(protocol)(pool, config)
        audit.record(
            tool="send_frame",
            target=f"{protocol}://{host}:{port} unit={unit}",
            frame_hex=frame_hex,
        )
        return await adapter.send_raw(
            Target(protocol=protocol, host=host, port=port, unit=unit),
            frame_hex,
            timeout_ms,
        )


def main() -> None:
    """console script 入口: 默认 stdio transport。"""
    app = create_app()
    app.run(show_banner=False)


if __name__ == "__main__":
    main()



