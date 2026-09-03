"""安全闸门与审计日志 (ARCHITECTURE.md D5)。

- allow_write=False 时写类工具在注册层即不存在 (server.py 控制), 本模块
  负责开启后的审计落地。
- 审计日志不可关 (HANDOFF 红线 2): 所有写/发送动作必须逐条记录。
"""

from __future__ import annotations

import json
import time
from pathlib import Path


class AuditLog:
    """JSONL 追加写审计日志。目录不存在自动创建 (HANDOFF 第 4 节)。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        tool: str,
        target: str,
        frame_hex: str,
        caller: str = "mcp",
    ) -> None:
        """逐条追加一行 JSON。写入失败不应中断主流程, 但要留痕到 stderr。

        注: 审计条目只含帧 hex 与目标标识, 不含业务数据 (secrets.md 红线)。
        """
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool": tool,
            "target": target,
            "frame_hex": frame_hex,
            "caller": caller,
        }
        line = json.dumps(entry, ensure_ascii=False)
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            # 审计写入失败不阻断工具调用, 但必须在服务端可观测
            import sys

            print(f"plctap: audit log write failed: {self.path}", file=sys.stderr)
