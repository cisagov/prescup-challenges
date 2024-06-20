
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import can
import time

# Create connection to server
bus = can.Bus('ws://10.3.3.223:54701/',
    bustype='remote',
    bitrate=500000,
    receive_own_messages=True)

while True:
    msg = can.Message(arbitration_id=0xa1223a, data=[70, 60, 30, 80, 50, 20, 10, 40])
    bus.send(msg)
    msg2 = bus.recv(1)
    print(msg2)
    time.sleep(3)

#bus.shutdown()
