# -*- coding: utf-8 -*-
"""plctap x ProtoForge 实机联测: 写->读->解释 完整闭环"""
import asyncio, json
from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
from plctap.protocols.modbus.adapter import ModbusAdapter, ModbusError

TARGET = Target(protocol="modbus", host="127.0.0.1", port=15020, unit=1)

async def main():
    adapter = ModbusAdapter(ConnectionPool(), PlctapConfig())
    out = {}

    # 1) probe
    out["1_probe"] = (await adapter.probe(TARGET)).model_dump()

    # 2) 写预置: fc06 addr1=1234, addr2=5678, addr3=0xFFFF
    w1 = await adapter.write(TARGET, address=1, values=[1234])
    w2 = await adapter.write(TARGET, address=2, values=[5678])
    w3 = await adapter.write(TARGET, address=3, values=[0xFFFF])
    out["2_write_fc06"] = {"frames": [w1["request_frame"], w2["request_frame"], w3["request_frame"]],
                           "echo_ok": all(w["request_frame"] == w["response_frame"] for w in (w1, w2, w3))}

    # 3) 读回验证 uint16
    r = await adapter.read(TARGET, address=1, count=3, datatype="uint16")
    out["3_read_uint16"] = {"raw": r.raw_registers, "interpreted": r.interpreted, "elapsed_ms": r.elapsed_ms}

    # 4) float32: 3.14 = 0x4049 0x0FDB 写入 addr11-12, 读回
    await adapter.write(TARGET, address=11, values=[0x4049])
    await adapter.write(TARGET, address=12, values=[0x0FDB])
    rf = await adapter.read(TARGET, address=11, count=2, datatype="float32", byteorder="big")
    out["4_read_float32"] = {"raw": rf.raw_registers, "interpreted": rf.interpreted}

    # 5) fc05 写线圈
    wc = await adapter.write(TARGET, address=5, values=[1], point_type="coil")
    out["5_write_fc05_coil"] = {"frame": wc["request_frame"], "echo_ok": wc["request_frame"] == wc["response_frame"]}

    # 6) 越界读 -> 异常
    try:
        await adapter.read(TARGET, address=200, count=1)
        out["6_out_of_range"] = "NO EXCEPTION (unexpected)"
    except ModbusError as e:
        out["6_out_of_range"] = str(e)

    print(json.dumps(out, ensure_ascii=False, indent=1))

asyncio.run(main())
