
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import can
import time
import random

# Create connection to server
bus = can.Bus('ws://10.3.3.223:54701/', bustype='remote', bitrate=500000, receive_own_messages=True)

while True:
    rand1 = random.randint(0, 99)
    rand2 = random.randint(0, 99)
    rand3 = random.randint(0, 99)
    rand4 = random.randint(0, 99)
    rand5 = random.randint(0, 99)
    rand6 = random.randint(0, 99)
    rand7 = random.randint(0, 99)
    rand8 = random.randint(0, 99)

    msg = can.Message(arbitration_id=0xc6890a, data=[rand1, rand2, rand3, rand4, rand5, rand6, rand7, rand8])
    bus.send(msg)
    msg2 = bus.recv(1)
    print(msg2)
    time.sleep(5)

#bus.shutdown()
