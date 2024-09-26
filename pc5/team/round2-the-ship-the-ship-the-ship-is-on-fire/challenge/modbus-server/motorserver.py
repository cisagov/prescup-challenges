
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

def run_async_server():
    software_version = "1.0.0"
    
    #with open('software_version.txt', 'r') as reader:
    #software_version = reader.read()

    nreg = 200
    coil_values = [False] * nreg
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [15]*nreg),
        co=ModbusSequentialDataBlock(0, coil_values),
        hr=ModbusSequentialDataBlock(0, [17]*nreg),
        ir=ModbusSequentialDataBlock(0, [18]*nreg))

    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Vendor Name=MerchCodes"
    identity.ProductCode = "Product Code=ScadaMotorControler"
    identity.VendorUrl = "http://scada.merch.codes"
    identity.ProductName = "Product Name=Motor Controller Server"
    identity.ModelName = "Motor Controller"
    identity.MajorMinorRevision = "Software Version=" + software_version

    StartTcpServer(context=context, host="10.3.3.201", identity=identity,\
    address=("10.3.3.201", 502))

if __name__ == "__main__":
    print("Modbus server started on localhost port 502")
    run_async_server()

