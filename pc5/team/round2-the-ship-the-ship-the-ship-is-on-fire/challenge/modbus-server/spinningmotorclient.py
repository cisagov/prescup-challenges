
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import time
import random
from pymodbus.client import ModbusTcpClient

# Modbus server address and port
# server_address = "10.3.3.201"
# server_port = 502

# Modbus holding register address
register_address = 0 

# Initialize Modbus client
client = ModbusTcpClient("10.3.3.201", port=502)

# Initialize RPM and increment values
rpm = 2000
increment = 10

while True:
    try:
        client.connect()
        # Read the current state of coils
        coil1_state = client.read_coils(0, 1).bits[0]
        coil2_state = client.read_coils(1, 1).bits[0]

        # Check the state of coil1 (increment)
        if coil1_state:
            rpm += 100  # Increment by 100
            client.write_coils(0, [False])  # Set coil1 to 0
            client.write_coils(1, [False])  # Set coil2 to 0 - new line
            increment = random.randint(1, 50)
            print("rpm is increasing")

        # Check the state of coil2 (decrement)
        elif coil2_state:
            rpm -= 100  # Decrement by 100
            client.write_coils(1, [False])  # Set coil2 to 0
            client.write_coils(0, [False])  # Set coil1 to 0 - new line
            increment = random.randint(1, 50)
            increment = increment * -1
            print("rpm is decreasing")

        # Update RPM with the increment value
        if rpm + increment <= 3000:
            rpm += increment
        print("rpm = "+ str(rpm))

        # Write RPM to the holding register
        print("writing rpm to register")
        client.write_register(0, rpm, skip_encoder=True)
        client.close()
    except Exception as e:
            print(e)
    # Sleep for 1 second
    time.sleep(1)


