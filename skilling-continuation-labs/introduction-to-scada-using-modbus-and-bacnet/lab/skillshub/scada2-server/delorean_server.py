
# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from pymodbus.server.sync import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

def run_async_server():
    num_registers = 50

    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [15] * num_registers),
        co=ModbusSequentialDataBlock(0, [15] * num_registers),
        hr=ModbusSequentialDataBlock(0, [0] * num_registers),
        ir=ModbusSequentialDataBlock(0, [15] * num_registers))

    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Vendor Name=DeLorean"
    identity.ProductCode = "Product Code=DMC12_SCADA_Server"
    identity.VendorUrl = "http://scada.skills.hub"
    identity.ProductName = "Product Name=DMC-12 SCADA Server"
    identity.ModelName = "Model Name=DMC-12"
    identity.MajorMinorRevision = "Software Version=1.5.50" 
  
    # coolant percent = 67
    # fuel percent = 75
    # speed mph = 55
    # reactor temp = 181
    values_to_write = [67, 75, 55, 780]
    #1 or 0x01 for Coils
    #2 or 0x02 for Discrete Inputs
    #3 or 0x03 for Holding Registers
    #4 or 0x04 for Input Registers
    context[0].setValues(3, 0, values_to_write)

    StartTcpServer(context=context, identity=identity, address=("10.3.3.56", 502))

if __name__ == "__main__":
    print("Modbus server running on port 502")
    run_async_server()



