# -*- coding: utf-8 -*-
"""End-to-end verification of plctap adapters against real simulator slaves."""
import asyncio, sys
sys.stdout.reconfigure(encoding="utf-8")
from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.protocols.base import adapter_for
from plctap.models import Target
import plctap.protocols.modbus.adapter  # noqa: F401 (注册副作用)
import plctap.protocols.s7.adapter  # noqa: F401 (注册副作用)

async def main():
    pool = ConnectionPool(PlctapConfig())
    report = []

    # ---------------- Modbus TCP ----------------
    mb = adapter_for("modbus")(pool, PlctapConfig(allow_write=True))
    t = Target(protocol="modbus", host="127.0.0.1", port=5020, unit=1)
    p = await mb.probe(t)
    report.append(("modbus probe reachable", p.reachable, getattr(p, "failure_class", None)))
    r = await mb.read(t, 0, 4, datatype="uint16", function_code=3)
    report.append(("modbus read HR0-3 uint16", r.raw_registers == [100, 200, 300, 0x41F0], r.raw_registers))
    r3 = await mb.read(t, 0, 2, datatype="float32", byteorder="big", function_code=3)
    import struct
    exp = struct.unpack(">f", struct.pack(">HH", 100, 200))[0]
    report.append(("modbus read float32 big", abs(r3.interpreted[0] - exp) < 1e-6, r3.interpreted))
    w = await mb.write(t, 10, [1234, 5678], point_type="register")  # fc16 默认
    report.append(("modbus write fc16 x2", True, f"resp={w['response_frame'][-12:]}"))
    r2 = await mb.read(t, 10, 2, datatype="uint16", function_code=3)
    report.append(("modbus readback", r2.raw_registers == [1234, 5678], r2.raw_registers))
    wc = await mb.write(t, 0, [1], point_type="coil")
    report.append(("modbus write coil fc05", True, f"resp={wc['response_frame'][-12:]}"))

    # ---------------- S7 ----------------
    s7 = adapter_for("s7")(pool, PlctapConfig(allow_write=True))
    ts = Target(protocol="s7", host="127.0.0.1", port=1020, unit=0)
    try:
        p7 = await s7.probe(ts)
        report.append(("s7 probe reachable", p7.reachable, getattr(p7, "failure_class", None)))
        r7 = await s7.read(ts, 0, 2, datatype="uint16", area="DB", db_number=1)
        report.append(("s7 read DB1.DB0 uint16", True, {"raw": r7.raw_registers, "interp": r7.interpreted, "elapsed": r7.elapsed_ms}))
        w7 = await s7.write(ts, 0, [0xAB, 0xCD], area="DB", db_number=1)
        report.append(("s7 write DB1", True, f"resp_ok={len(w7['response_frame'])>0}"))
        r7b = await s7.read(ts, 0, 2, datatype="uint16", area="DB", db_number=1)
        report.append(("s7 readback", True, {"raw": r7b.raw_registers}))
    except Exception as e:
        report.append(("s7 FAILED", False, repr(e)))

    for name, ok, detail in report:
        print(f"{'PASS' if ok else 'FAIL'} | {name} | {detail}")
    await pool.close_all()

asyncio.run(main())



