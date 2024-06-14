
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from pymodbus.client import ModbusTcpClient
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadBuilder
from pymodbus.payload import BinaryPayloadDecoder
import time

print("Starting Reactor Client")

client = ModbusTcpClient("10.2.2.101", port=502)
client2 = ModbusTcpClient("10.2.2.102", port=502)
reg = 0
address = 0
continueChecking = True
clientContinue = True
clientContinue2 = True

while continueChecking:
    try:
        client.connect()

        data = [0]
        data = client.read_holding_registers(reg, 1).registers
        print("Read Reactor 1", data)

        if data[0] > 200:
          clientContinue = False

        client.close()
    except Exception as e:
        print(f"Reactor 1: {e}")

    try:
        client2.connect()

        data2 = [0]
        data2 = client2.read_holding_registers(reg, 1).registers
        print("Read Reactor 2", data2)

        if data2[0] > 250:
            clientContinue2 = False

        client2.close()
    except Exception as e:
        print(f"Reactor 2: {e}")

    if clientContinue == False and clientContinue2 == False:
        with open("reactor_complete.txt", "w") as file1:
            file1.write("reactor_shutdown_complete")
        continueChecking = False            

    time.sleep(10.0)

