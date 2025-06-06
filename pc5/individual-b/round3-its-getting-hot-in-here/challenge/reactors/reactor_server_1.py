
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

def run_async_server():
    software_version = ""

    with open('software_version.txt', 'r') as reader:
        software_version = reader.read()

    num_registers = 50

    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [15] * num_registers),
        co=ModbusSequentialDataBlock(0, [15] * num_registers),
        hr=ModbusSequentialDataBlock(0, [165] * num_registers),
        ir=ModbusSequentialDataBlock(0, [15] * num_registers))

    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Vendor Name=MerchCodes"
    identity.ProductCode = "Product Code=ScadaReactorServer"
    identity.VendorUrl = "http://scada.merch.codes"
    identity.ProductName = "Product Name=Scada Reactor Server"
    identity.ModelName = "Model Name=Reactor Model One"
    identity.MajorMinorRevision = "Software Version=" + software_version
  
    StartTcpServer(context=context, host="10.2.2.101", identity=identity, address=("10.2.2.101", 502))

if __name__ == "__main__":
    print("Modbus server running on port 502")
    run_async_server()

