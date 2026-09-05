# -*- coding: utf-8 -*-
"""Modbus TCP slave simulator for plctap verification (pymodbus 3.9).

pymodbus 内部 getValues 会做 address+1 偏移, 因此 block[0] 放占位 0,
外部地址 0 对应 block[1]。
"""
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

def build_context():
    hr = ModbusSequentialDataBlock(0, [0, 100, 200, 300, 0x41F0, 0x0000, 42, 7, 0, 0, 0])
    co = ModbusSequentialDataBlock(0, [0, 1, 0, 1, 1] + [0]*16)
    di = ModbusSequentialDataBlock(0, [0]*32)
    ir = ModbusSequentialDataBlock(0, [0, 5]*16)
    slave = ModbusSlaveContext(hr=hr, co=co, di=di, ir=ir)
    return ModbusServerContext(slaves=slave, single=True)

if __name__ == "__main__":
    print("Modbus TCP slave on 127.0.0.1:5020", flush=True)
    StartTcpServer(context=build_context(), address=("127.0.0.1", 5020))

