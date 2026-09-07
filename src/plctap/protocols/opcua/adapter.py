"""OPC UA 适配器 (v0.6): 连接级诊断 —— probe / read / browse, 只读。

与其他端点的差异 (会话式协议, ADD_PROTOCOL.md 有偏差条款):
- 传输与会话 (HEL/OPN/CreateSession/ActivateSession) 由 asyncua 封装,
  没有原始帧概念 —— send_raw/parse_frame/validate_frame 均显式声明
  不适用 (元数据经 server.list_protocols 的类级比较如实上报, 非缺陷);
- asyncua Client 自管 TCP 传输, 不进连接池; pool 只贡献目标级锁做
  并发串行化。每次调用独立建会话: 诊断场景调用稀疏, 正确性优先于
  握手延迟 (本机实测完整握手 ~2ms, 局域网百 ms 级);
- 安全策略仅 SecurityPolicy None (诊断场景声明); 端点要求签名/加密时
  落 connected_but_no_reply / ProtocolError —— 本身就是诊断结论
  (kb/opcua.yaml);
- asyncua 惰性导入: 未安装时报错指向安装命令, 不影响 server 启动
  其他端点 (pyproject 已声明运行时依赖, 正常安装路径不会触发)。
"""

from __future__ import annotations

import re
import time

from plctap.models import ProbeResult, ReadResult, Target
from plctap.protocols.base import ProtocolAdapter, ProtocolError, register_adapter
from plctap.protocols.opcua import meta as _meta

# NodeId 语法闸 (适配器侧兜底, server 层 _validate_address 之外):
# ns=<uint>;<i|s|g|b>=<值> —— 完整合法性由 asyncua 解析时给出精确报错
_NODE_ID_RE = re.compile(r"^ns=\d+;(i|s|g|b)=\S+$")

# browse 单次输出硬上限 (MCP token 预算; 每条 ~150B 序列化, 200 条 ~30KB)
_BROWSE_MAX_CHILDREN = 200

# 探测用的规范强制节点: Server_ServerArray (应用 URI 列表, 任何合规
# server 必须可读) —— 不依赖任何厂商地址空间
_SERVER_ARRAY_NODE = "ns=0;i=2254"


def _require_asyncua():
    """惰性导入 asyncua, 缺失时给出安装指向 (不影响 server 启动)。"""
    try:
        from asyncua import Client  # noqa: F401
        from asyncua.ua import status_codes, uaerrors  # noqa: F401

        return Client, uaerrors, status_codes
    except ImportError as e:
        raise RuntimeError("opcua 端点需要 asyncua: pip install asyncua (或 uv sync)") from e


def _status_name(status_codes, code: int) -> str:
    """UA 状态码 -> 'BadNodeIdUnknown' 形式名称 (取不到时回退 hex)。"""
    try:
        return status_codes.get_name_and_doc(code)[0]
    except Exception:  # noqa: BLE001 - 未知码不阻断错误上报
        return f"{code:#010x}"


@register_adapter
class OpcuaAdapter(ProtocolAdapter):
    name = "opcua"
    meta = _meta.META

    # ------------------------------------------------------------ 地址

    def _node_id(self, address) -> str:
        if not isinstance(address, str) or not _NODE_ID_RE.match(address.strip()):
            raise ValueError(
                "opcua 的 address 必须是 NodeId 字符串 (如 'ns=2;i=5' 或 "
                f"'ns=2;s=Demo.Double'), got {address!r}"
            )
        return address.strip()

    # ------------------------------------------------------------ 会话

    async def _connect(self, target: Target, timeout: float):
        """独立会话: 每次调用全新 Client (见模块 docstring 连接策略)。"""
        Client, _, _ = _require_asyncua()
        return Client(f"opc.tcp://{target.host}:{target.port}/", timeout=timeout)

    # ------------------------------------------------------------ probe

    async def probe(self, target: Target) -> ProbeResult:
        Client, uaerrors, status_codes = _require_asyncua()
        timeout = self.timeout(None)
        client = None
        try:
            # 建连也在分类域内: refused/timeout 必须归因, 不能裸抛
            client = await self._connect(target, timeout)
            await client.connect()
            # 最小读 = Server_ServerArray (规范强制节点, 全程只读)
            server_array = await client.get_node(_SERVER_ARRAY_NODE).read_value()
            # 断连前取样 (disconnect 后属性可能被清理); 用完整类名
            # (SecurityPolicyNone / SecurityPolicyBasic256Sha256) 避免与
            # Python None 字面量混淆
            policy = type(client.security_policy).__name__
        except uaerrors.UaStatusCodeError as e:
            # 服务端在 UA 语义层主动拒绝 (在线且回 UA 状态码)
            code = getattr(e, "code", None)
            return ProbeResult(
                reachable=True, failure_class="exception_response",
                exception_code=code, layer_hint="application",
            )
        except TimeoutError:
            return ProbeResult(reachable=False, failure_class="timeout",
                               layer_hint="connectivity")
        except ConnectionRefusedError:
            return ProbeResult(reachable=False, failure_class="connection_refused",
                               layer_hint="connectivity")
        except OSError:
            # 网络不可达等与 refused 同属"连接未建立" (TimeoutError 已先行)
            return ProbeResult(reachable=False, failure_class="connection_refused",
                               layer_hint="connectivity")
        except Exception:
            # 会话/安全策略握手失败: None 被禁用、证书不信任、非 UA 服务
            return ProbeResult(reachable=False, failure_class="connected_but_no_reply",
                               layer_hint="protocol")
        finally:
            if client is not None:
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001 - 断连失败不影响探测结论
                    pass
        return ProbeResult(
            reachable=True, layer_hint="application",
            identity={
                "security_policy": policy,
                "server_array": [str(u) for u in list(server_array)[:4]],
            },
        )

    # ------------------------------------------------------------ read

    async def read(
        self,
        target: Target,
        address,
        count: int = 1,
        datatype: str | None = None,
        byteorder: str = "big",
        timeout_ms: int | None = None,
        **options,
    ) -> ReadResult:
        """读节点值 (返回 asyncua 原生类型, 标量或数组)。

        address = NodeId 字符串; count = 数组节点返回元素上限
        (0 = 全部), 标量节点忽略。datatype/byteorder 不参与解释 ——
        OPC UA 值自带类型 (UA 内建类型系统), 这是它与寄存器式协议的
        本质区别; 传入时仅做记录不生效。
        """
        Client, uaerrors, status_codes = _require_asyncua()
        node_id = self._node_id(address)
        timeout = self.timeout(timeout_ms)
        started = time.perf_counter()
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            client = await self._connect(target, timeout)
            try:
                await client.connect()
                value = await client.get_node(node_id).read_value()
            except uaerrors.UaStatusCodeError as e:
                code = getattr(e, "code", 0)
                raise ProtocolError(
                    f"opcua read failed: {_status_name(status_codes, code)} "
                    f"({code:#010x}) for node {node_id!r}"
                ) from None
            except TimeoutError:
                raise ProtocolError(
                    f"timeout waiting for node read from {key.target}"
                ) from None
            finally:
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001 - 断连失败不吞业务异常
                    pass
        if isinstance(value, list) and count and count > 0:
            value = value[:count]
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return ReadResult(
            target=target,
            address=node_id,
            # 会话协议无原始帧; 留说明性标记 (帧级工具对该协议显式拒绝)
            request_frame="opcua: Read service (session protocol, no frame-level diagnosis)",
            raw_registers=[],
            interpreted=value,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------ browse

    async def browse(
        self,
        target: Target,
        node: str = "ns=0;i=85",
        limit: int = 200,
        timeout_ms: int | None = None,
        **options,
    ) -> dict:
        """从 node 展开一层子节点 (Objects 文件夹 = ns=0;i=85)。

        输出预算: 子节点数硬上限 _BROWSE_MAX_CHILDREN, 超出时
        truncated=True 且 total 给出全量 (sentinel 语义, 同 parse_pcap)。
        """
        Client, uaerrors, status_codes = _require_asyncua()
        node_id = self._node_id(node)
        cap = max(0, min(int(limit), _BROWSE_MAX_CHILDREN))
        timeout = self.timeout(timeout_ms)
        key = self.key_for(target)
        async with self.pool.lock_for(key):
            client = await self._connect(target, timeout)
            shown: list[dict] = []
            try:
                await client.connect()
                children = await client.get_node(node_id).get_children()
                # 逐节点属性读取必须在连接存活期内 —— Node 是懒加载的,
                # disconnect 后再读会得到 "Connection is not open"
                for child in children[:cap]:
                    display = await child.read_display_name()
                    node_class = await child.read_node_class()
                    shown.append({
                        "node_id": child.nodeid.to_string(),
                        "display_name": getattr(display, "Text", None)
                        if display is not None else None,
                        "node_class": getattr(node_class, "name", str(node_class)),
                    })
            except uaerrors.UaStatusCodeError as e:
                code = getattr(e, "code", 0)
                raise ProtocolError(
                    f"opcua browse failed: {_status_name(status_codes, code)} "
                    f"({code:#010x}) for node {node_id!r}"
                ) from None
            except TimeoutError:
                raise ProtocolError(
                    f"timeout waiting for browse from {key.target}"
                ) from None
            finally:
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
        return {
            "node": node_id,
            "children": shown,
            "total": len(children),
            "shown": len(shown),
            "truncated": len(children) > len(shown),
        }
