"""IEC 104 与 lib60870 (MZ Automation 官方实现) 的双向交叉验证 e2e。

前置 (本地可用, CI 缺失自动跳过):
- dotnet SDK
- .tmp/lib60870net/ 官方库源码: git clone --depth 1
  https://github.com/mz-automation/lib60870.NET .tmp/lib60870net

server 模式预置: 单点遥信 200..203 = [1,0,1,0], 短浮点 300..302 =
[0.25, 0.5, 0.75] —— plctap 读值与官方 server 逐值比对;
client 模式连 plctap 钓鱼监听, 总召后解析罐头帧 (官方 client 侧验证)。
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("plctap")

_BENCH_DIR = Path(__file__).parent / "bench_iec104"
_LIB_DIR = Path(__file__).parents[2] / ".tmp" / "lib60870net"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(shutil.which("dotnet") is None, reason="dotnet SDK 不可用"),
    pytest.mark.skipif(not _LIB_DIR.exists(), reason=".tmp/lib60870net 官方源码未克隆"),
]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"bench server 未在 {port} 监听")


def _run_bench(mode: str, port: int) -> subprocess.Popen:
    return subprocess.Popen(
        ["dotnet", "run", "--project", str(_BENCH_DIR / "i104bench.csproj"),
         "--", mode, str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
    )


def test_plctap_adapter_reads_lib60870_server():
    """plctap 读官方 server 预置点位 (总召收集, 双向序号状态维护)。"""
    port = _free_port()
    proc = _run_bench("server", port)
    try:
        _wait_port(port)

        import asyncio
        from plctap.config import PlctapConfig
        from plctap.conn.manager import ConnectionPool
        from plctap.models import Target
        from plctap.protocols.iec104.adapter import Iec104Adapter

        async def run():
            pool = ConnectionPool(PlctapConfig())
            ad = Iec104Adapter(pool, PlctapConfig())
            t = Target(protocol="iec104", host="127.0.0.1", port=port, unit=1)
            sp = await ad.read(t, 200, 4)
            mv = await ad.read(t, 300, 3, datatype="float32")
            await pool.close_all()
            return sp.raw_registers, mv.interpreted

        raw, floats = asyncio.run(run())
        assert raw == [1, 0, 1, 0]
        assert floats == pytest.approx([0.25, 0.5, 0.75])
    finally:
        proc.kill()


def test_lib60870_client_reads_plctap_listener():
    """官方 client 连 plctap 钓鱼监听: 总召罐头帧被官方实现正确解码。"""
    import asyncio
    from plctap.listener import ListenerRegistry

    async def run():
        reg = ListenerRegistry()
        info = await reg.start("iec104", "127.0.0.1", 0, "respond_normal", idle_timeout_sec=60)
        port = info["port"]
        try:
            proc = await asyncio.create_subprocess_exec(
                "dotnet", "run", "--project", str(_BENCH_DIR / "i104bench.csproj"),
                "--", "client", str(port),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), 60)
            return out.decode("utf-8", errors="replace")
        finally:
            if proc.returncode is None:
                proc.kill()
            await reg.stop(port)

    out = asyncio.run(run())
    assert "M_SP 200 1" in out and "M_SP 201 0" in out
    assert "M_ME_NC 300 0" in out and "M_ME_NC 301 0.25" in out
    assert "CLIENT DONE" in out
