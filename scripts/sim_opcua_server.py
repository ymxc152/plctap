# -*- coding: utf-8 -*-
"""OPC UA 台架仿真器: asyncua server, 预置 plctap 验收演示节点。

用法 (仓库根目录):
    uv run python scripts/sim_opcua_server.py            # 端口自动分配
    uv run python scripts/sim_opcua_server.py --port 4840

预置节点 (ns=2, uri=http://plctap.demo):
    Demo/Boolean  = True
    Demo/Double   = 3.1415927
    Demo/String   = "hello plctap"
    Demo/Array    = [1.0, 2.0, 3.0]           (Double 数组, count 截断演示)
    Demo/Big/N0..N249                           (250 个节点, browse 预算演示)
安全策略: 按请求端点默认 (含 None), 供诊断模式连接。

stdout 打印 "OPCUA_SIM_PORT=<n>" 供脚本化取用; Ctrl-C 停止。
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from asyncua import Server, ua  # noqa: E402


async def main(port: int) -> None:
    logging.basicConfig(level=logging.WARNING)
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}/plctap/demo/")
    server.set_server_name("plctap OPC UA demo bench")
    idx = await server.register_namespace("http://plctap.demo")

    demo = await server.nodes.objects.add_folder(
        ua.NodeId("Demo", idx), ua.QualifiedName("Demo", idx)
    )
    await demo.add_variable(ua.NodeId("Demo.Boolean", idx), ua.QualifiedName("Boolean", idx), True)
    await demo.add_variable(ua.NodeId("Demo.Double", idx), ua.QualifiedName("Double", idx), 3.1415927)
    await demo.add_variable(ua.NodeId("Demo.String", idx), ua.QualifiedName("String", idx), "hello plctap")
    await demo.add_variable(ua.NodeId("Demo.Array", idx), ua.QualifiedName("Array", idx), [1.0, 2.0, 3.0])

    big = await demo.add_folder(ua.NodeId("Demo.Big", idx), ua.QualifiedName("Big", idx))
    for i in range(250):
        await big.add_variable(
            ua.NodeId(f"Demo.Big.N{i}", idx), ua.QualifiedName(f"N{i}", idx), i
        )

    await server.start()
    real_port = server.bserver._server.sockets[0].getsockname()[1]
    print(f"OPCUA_SIM_PORT={real_port}", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="plctap OPC UA 台架仿真器")
    ap.add_argument("--port", type=int, default=0, help="监听端口 (0=自动分配)")
    try:
        asyncio.run(main(ap.parse_args().port))
    except KeyboardInterrupt:
        pass
