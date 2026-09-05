# -*- coding: utf-8 -*-
"""S7 server simulator for plctap verification (python-snap7 3.x, pure python server)."""
import time
import snap7
from snap7.type import SrvArea

srv = snap7.Server(log=False)

db1 = bytearray(100)
db1[0:8] = bytes([0x12, 0x34, 0x56, 0x78, 0x41, 0xF0, 0x00, 0x00])  # 已知模式
db1[10:12] = bytes([0xFF, 0xFF])
srv.register_area(SrvArea.DB, 1, db1)

mk = bytearray(64)
mk[0:8] = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x42, 0x48, 0x00, 0x00])
srv.register_area(SrvArea.MK, 0, mk)

srv.start(tcp_port=1020)
print("S7 server listening on 127.0.0.1:1020 (DB1=100B, MK=64B)", flush=True)
while True:
    time.sleep(1)
