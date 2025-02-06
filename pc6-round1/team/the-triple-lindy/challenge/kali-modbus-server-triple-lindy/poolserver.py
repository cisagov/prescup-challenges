#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#

from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

def run_async_server():
    software_version = "1.1.9"
    num_registers = 50

    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * num_registers),
        co=ModbusSequentialDataBlock(0, [0] * num_registers),
        hr=ModbusSequentialDataBlock(0, [0, 7, 3, 100]),
        ir=ModbusSequentialDataBlock(0, [9, 6, 150]))

    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Vendor Name=Automated Pool Management"
    identity.ProductCode = "Product Code=PCM v1.1.9"
    identity.VendorUrl = "http://apm.merch.codes"
    identity.ProductName = "Product Name=Pool Chemical Manager"
    identity.ModelName = "Model Name=PCM v1.1.9"
    identity.MajorMinorRevision = "Software Version=" + software_version

    StartTcpServer(context=context, host="10.1.1.125", identity=identity, address=("10.1.1.125", 502))

if __name__ == "__main__":
    print("Modbus server running on port 502")
    run_async_server()


