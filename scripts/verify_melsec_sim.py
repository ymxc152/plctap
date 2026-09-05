# -*- coding: utf-8 -*-
import asyncio, sys
sys.stdout.reconfigure(encoding="utf-8")
from plctap.config import PlctapConfig
from plctap.conn.manager import ConnectionPool
from plctap.models import Target
import plctap.protocols.melsec.adapter  # noqa

async def main():
    pool = ConnectionPool(PlctapConfig())
    mc = plctap.protocols.melsec.adapter.MelsecAdapter(pool, PlctapConfig())
    t = Target(protocol="melsec", host="127.0.0.1", port=6000, unit=0)
    p = await mc.probe(t)
    print("probe:", p.reachable, p.failure_class, p.layer_hint)
    r = await mc.read(t, 0, 2, datatype="uint16", device="D")
    print("read D0..1:", r.raw_registers, r.interpreted, "frame:", r.request_frame)
    await pool.close_all()

asyncio.run(main())
