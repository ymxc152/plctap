# -*- coding: utf-8 -*-
"""Modbus TCP slave simulator for plctap verification (双 API 兼容).

外部地址布局 (两代 API 共用): 0..3 -> [100, 200, 300, 0x41F0] (float32 @3 = 30.0),
10/11 留给写验证。pymodbus 3.15 起弃用 ModbusSlaveContext/ModbusServerContext
(legacy 包装会丢失块起始地址), 改用 SimDevice/SimData —— 外部地址 0 直接对应
SimData 偏移 0, 无老版本的 address+1 偏移 (与 tests/e2e/test_cross_vendor.py 同思路)。
"""
from pymodbus.server import StartTcpServer

_HR = [100, 200, 300, 0x41F0, 0, 0, 42, 7, 0, 0] + [0] * 10


def _context_new():
    from pymodbus.simulator.simdata import DataType, SimData
    from pymodbus.simulator.simdevice import SimDevice

    hr = SimData(address=0, count=20, values=_HR, datatype=DataType.REGISTERS)
    co = SimData(address=0, count=16, datatype=DataType.BITS)
    di = SimData(address=0, count=16, datatype=DataType.BITS)
    ir = SimData(address=0, count=16, datatype=DataType.REGISTERS)
    return SimDevice(id=1, simdata=([co], [di], [hr], [ir]))


def _context_legacy():
    # pymodbus <3.15: getValues 做 address+1 偏移, block[0] 放占位 0
    from pymodbus.datastore import (
        ModbusSequentialDataBlock,
        ModbusServerContext,
        ModbusSlaveContext,
    )

    hr = ModbusSequentialDataBlock(0, [0] + _HR)
    co = ModbusSequentialDataBlock(0, [0, 1, 0, 1, 1] + [0] * 16)
    di = ModbusSequentialDataBlock(0, [0] * 32)
    ir = ModbusSequentialDataBlock(0, [0, 5] * 16)
    return ModbusServerContext(
        slaves=ModbusSlaveContext(hr=hr, co=co, di=di, ir=ir), single=True
    )


def build_context():
    try:
        return _context_new()
    except ImportError:
        return _context_legacy()


if __name__ == "__main__":
    print("Modbus TCP slave on 127.0.0.1:5020", flush=True)
    StartTcpServer(context=build_context(), address=("127.0.0.1", 5020))
