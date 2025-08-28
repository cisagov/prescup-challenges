
# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from time import sleep
from BAC0 import lite
from BAC0.core.devices.local.models import binary_value
from bacpypes.core import run, stop

# device settings
dev_ip = "10.3.3.101/24"
dev_port = 47808
dev_id = 1001

# start device
device = lite(ip=dev_ip, port=dev_port, deviceId=dev_id)

# Garage door open/close state (1=open, 0=closed)
binary_value(
instance=1,
name="GarageDoorState",
description="1 = Open, 0 = Closed",
presentValue=0,
is_commandable=True,
).add_objects_to_application(device)

try:
    while True: 
        sleep(1)
except KeyboardInterrupt:
    stop()

