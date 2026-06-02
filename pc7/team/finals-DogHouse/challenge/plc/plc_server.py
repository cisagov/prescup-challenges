#!/usr/bin/env python3
import threading
import time
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock

PROTECTED_REGISTERS = {10, 31} 

class ProtectedDataBlock(ModbusSequentialDataBlock):
    def __init__(self, address, values, protected):
        super().__init__(address, values)
        self._protected = protected
        self._bypass = False  

    def setValues(self, address, values):
        # block writes to protected registers
        if self._bypass:
            return super().setValues(address, values)
        for i, v in enumerate(values):
            reg = address + i
            if reg not in self._protected:
                super().setValues(reg, [v])
            else:
                print(f"[PLC] Blocked external write to HR[{reg}]")

    def internal_write(self, address, values):
        self._bypass = True
        try:
            super().setValues(address, values)
        finally:
            self._bypass = False


MODBUS_PORT = 5020      
UNIT_ID = 1

FILL_RATE = 10           
DRAIN_RATE = 20          

TICK_SEC = 1.0           


#holding registers
REG_LEVEL       = 10   # 0-100 
REG_PUMP        = 11   # 0=off,1=on 
REG_LIMIT       = 20   # 0-100 
REG_VALVE       = 21   # 0=closed,1=open 
REG_TOKEN_FLAG  = 31   


# Initial state
initial = [0]*100
initial[REG_LEVEL]  = 20
initial[REG_PUMP]   = 0
initial[REG_LIMIT] = 50
initial[REG_VALVE]  = 0
initial[REG_TOKEN_FLAG] = 0

slave_block = ProtectedDataBlock(0, initial, PROTECTED_REGISTERS)
store   = ModbusSlaveContext(hr=slave_block, zero_mode=True)
context = ModbusServerContext(slaves=store, single=True)
lock    = threading.Lock()

def get_hr(i):
    with lock:
        return context[0].getValues(3, i, count=1)[0]

def set_hr(i, v):
    with lock:
        slave_block.internal_write(i, [v])

def clamp01(x):  
    return 0 if x < 0 else 100 if x > 100 else x

def plc_loop():
    last_valve = get_hr(REG_VALVE)

    while True:
        time.sleep(TICK_SEC)

        level  = get_hr(REG_LEVEL)
        pump   = get_hr(REG_PUMP)
        limit = get_hr(REG_LIMIT)
        valve  = get_hr(REG_VALVE)


        if limit != clamp01(limit):
            limit = clamp01(limit)
            set_hr(REG_LIMIT, limit)
        if level != clamp01(level):
            level = clamp01(level)
            set_hr(REG_LEVEL, level)


        if valve == 1 and pump == 1:
            pump = 0
            set_hr(REG_PUMP, 0)


        if last_valve == 0 and valve == 1 and level == 100 and get_hr(REG_TOKEN_FLAG) == 0:
            print("[PLC] Valve opened at 100% → TOKEN!")
            set_hr(REG_TOKEN_FLAG, 1)


        if valve == 1:
 
            new_level = clamp01(level - DRAIN_RATE * TICK_SEC)
            if new_level != level:
                set_hr(REG_LEVEL, int(new_level))

        else:
            if pump == 1:
                if level < limit:
                    delta = FILL_RATE * TICK_SEC
                    new_level = level + delta
                    if new_level >= limit:
                        new_level = limit
                        # Stop the pump when limit reached
                        set_hr(REG_PUMP, 0)
                        pump = 0
                    set_hr(REG_LEVEL, int(clamp01(new_level)))
                else:
                    if pump != 0:
                        set_hr(REG_PUMP, 0)
                        pump = 0

        last_valve = valve

if __name__ == "__main__":
    threading.Thread(target=plc_loop, daemon=True).start()
    print(f"[PLC] Modbus server on 0.0.0.0:{MODBUS_PORT} (Unit {UNIT_ID})")
    StartTcpServer(context=context, address=("0.0.0.0", MODBUS_PORT))
