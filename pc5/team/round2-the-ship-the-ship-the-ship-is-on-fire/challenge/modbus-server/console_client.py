
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import time
import random
from pymodbus.client import ModbusTcpClient

# Modbus server address and port
server_address = "10.3.3.200"
server_port = 502

# # Modbus holding register addresses for room temps
# piloting_register_address = 0 
# engineering_register_address = 1
# dc__register_address = 2
# comms_register_address = 3
# pshuttle_register_address = 4
# ops_register_address = 5
# sshuttle_register_address = 6

##########################################
# Doors 1 - 6 = coil 1 - 6 
# Fire Suppression:
#   1 - Piloting - coil 7
#   2 - Engineering - coil 8
#   3 - DC - coil 9
#   4 - Comms - coil 10
#   5 - Ops - coil 11
# Smoke Sensors:
#   1 - Piloting - coil 12
#   2 - Engineering - coil 13
#   3 - DC - coil 14
#   4 - Comms - coil 15
#   5 - Pshuttle - coil 16
#   6 - Ops - coil 17
#   7 - Sshuttle - coil 18
##########################################


# Initialize Modbus client
client = ModbusTcpClient("10.3.3.200", port=502)
client.connect()
client.write_coils(16, [True]) # set off Smoke alarm 
client.write_coils(17, [True]) # set off Smoke alarm
client.close()

while True:
    try:
        client.connect()
        # Read the current state of door coils
        door1_state = client.read_coils(1, 1).bits[0]
        door2_state = client.read_coils(2, 1).bits[0]
        door3_state = client.read_coils(3, 1).bits[0]
        door4_state = client.read_coils(4, 1).bits[0]
        door5_state = client.read_coils(5, 1).bits[0]
        door6_state = client.read_coils(6, 1).bits[0]
        
        print("door states read")
        
        # If doors open, deactivate3 fire suppression
        if door1_state == False:
            # Room not Isolated
            client.write_coils(7, [False])  # Set coil7 to 0
            client.write_coils(8, [False])  # Set coil8 to 0
            print("Door 1 open, deactivated fire suppression")

        if door2_state == False:
            # Room not Isolated
            client.write_coils(8, [False])  # Set coil8 to 0
            client.write_coils(9, [False])  # Set coil9 to 0
            print("Door 2 open, deactivated fire suppression")

        if door3_state == False:
            # Room not Isolated
            client.write_coils(8, [False])  # Set coil8 to 0
            client.write_coils(10, [False])  # Set coil10 to 0
            print("Door 3 open, deactivated fire suppression")

        if door4_state == False:
            # Room not Isolated
            client.write_coils(8, [False])  # Set coil8 to 0
            client.write_coils(11, [False])  # Set coil11 to 0
            print("Door 4 open, deactivated fire suppression")

        #  Read Fire Suppression controls
        pilot_fs_state = client.read_coils(7, 1).bits[0]
        engineering_fs_state = client.read_coils(8, 1).bits[0]
        dc_fs_state = client.read_coils(9, 1).bits[0]
        comms_fs_state = client.read_coils(10, 1).bits[0]
        ops_fs_state = client.read_coils(11, 1).bits[0]

        #set temps
        print("writing temps to register")
        client.write_register(0, random.randint(70, 78), skip_encoder=True)
        client.write_register(1, random.randint(70, 78), skip_encoder=True)
        client.write_register(2, random.randint(70, 78), skip_encoder=True)
        client.write_register(3, random.randint(70, 78), skip_encoder=True)
        client.write_register(6, random.randint(70, 78), skip_encoder=True)
        client.write_coils(12, [False]) # turn off Smoke alarm
        client.write_coils(13, [False]) # turn off Smoke alarm
        client.write_coils(14, [False]) # turn off Smoke alarm
        client.write_coils(15, [False]) # turn off Smoke alarm
        client.write_coils(18, [False]) # turn off Smoke alarm
        if door4_state & ops_fs_state:
            client.write_register(4, random.randint(70, 78), skip_encoder=True) # Set Temp
            client.write_register(5, random.randint(70, 78), skip_encoder=True) # Set Temp
            client.write_coils(16, [False]) # Clear Smoke alarm 
            client.write_coils(17, [False]) # Clear Smoke alarm
            with open('fire_suppressed.txt', 'w') as flag_file:
                flag_file.write('fire_suppression_complete')
        else:
            client.write_register(4, random.randint(3800, 4000), skip_encoder=True)
            client.write_coils(16, [True]) # set off Smoke alarm 
            client.write_register(5, random.randint(3800, 4000), skip_encoder=True)
            client.write_coils(17, [True]) # set off Smoke alarm
    
    except Exception as e:
            print(e)

    # close connection
    client.close()

    # Sleep for 1 second
    time.sleep(1)

