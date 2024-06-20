
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from pymodbus.client import ModbusTcpClient
import time
import sys

#connection
client = ModbusTcpClient("10.3.3.201", port=502)
while True:
    try:
        client.connect()
        print("connected to server")
        rd = client.read_holding_registers(0, 1).registers
        print("Read", rd)
        #rd = client.read_holding_register(0,count=1, unit=0)
        #print("rpm is" + rd)
    
        print(rd[0])
        rpm = rd[0]

        # send control commands based on rpm
        if rpm == 0:
            print("rpm 0, exiting")
            sys.exit()
        elif rpm < 2100:
            print("rpm < 2100")
            client.write_coil(0, True, unit=0) #set coil 1 for speed up
            #client.write_coil(1, False, unit=0) #set coil 2 to 0 for do nothing
        elif rpm > 2900:
            print("rpm over 2999")
            client.write_coil(1, True, unit=0) #set coil 2 for slow down
            #client.write_coil(0, False, unit=0) #set coil 1 to 0 for do nothing
        client.close()
    except Exception as e:
        print(f"Connection fail, retrying...")
    print("sleeping for 10 sec")
    time.sleep(10)


