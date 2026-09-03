"""运行配置 (ARCHITECTURE.md 第 7 节)。

配置来源: 环境变量 (PLCTAP_*)。
理由: MCP stdio server 由客户端拉起 (claude_desktop_config.json 的 env 段 /
Codex config.toml 的 [mcp_servers.plctap].env), 环境变量是两个客户端都原生
支持的配置通道; 独立 TOML 文件还需约定查找路径与优先级, M1 阶段不引入。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_TRUE = {"1", "true", "yes", "on"}

_DEFAULT_AUDIT_LOG = Path.home() / ".plctap" / "audit.jsonl"


@dataclass(frozen=True)
class PlctapConfig:
    """server 运行参数, 与 ARCHITECTURE.md 第 7 节的配置样例一一对应。"""

    # 安全闸门 (D5): False 时写类工具根本不注册
    allow_write: bool = False
    # 连接池: 每目标 (protocol,host,port,unit) 同时持有的连接上限 (D1)
    pool_max_per_target: int = 2
    # 空闲连接回收阈值 (D1: 空闲 30s 回收)
    idle_timeout_sec: float = 30.0
    # 默认网络超时 (连接/收发各自独立计时)
    default_timeout_ms: int = 2000
    # JSONL 审计日志路径; 审计不可关 (HANDOFF 红线 2)
    audit_log: Path = _DEFAULT_AUDIT_LOG

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "PlctapConfig":
        env = os.environ if env is None else env
        return cls(
            allow_write=env.get("PLCTAP_ALLOW_WRITE", "").strip().lower() in _TRUE,
            pool_max_per_target=int(env.get("PLCTAP_POOL_MAX_PER_TARGET", "2")),
            idle_timeout_sec=float(env.get("PLCTAP_IDLE_TIMEOUT_SEC", "30")),
            default_timeout_ms=int(env.get("PLCTAP_DEFAULT_TIMEOUT_MS", "2000")),
            audit_log=Path(env.get("PLCTAP_AUDIT_LOG", str(_DEFAULT_AUDIT_LOG))),
        )
