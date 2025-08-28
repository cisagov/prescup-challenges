
# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from time import sleep
from BAC0 import lite
from BAC0.core.devices.local.models import binary_value, analog_value
from BAC0.core.devices.local.object import ObjectFactory
from bacpypes.core import run, stop, deferred
from bacpypes.primitivedata import Real
from threading import Timer

# device settings
dev_ip="10.3.3.103/24"
dev_port=47808
dev_id=3003

# start device
device= lite(ip=dev_ip, port=dev_port, deviceId=dev_id)

# arming state = 1 armed, 0 = disarmed
binary_value(
    instance=1,
    name="AlarmState",
    description="1 = Active, 0 = Disarmed",
    presentValue=1,
    is_commandable=False,
).add_objects_to_application(device)

#disarm Code 
analog_value(
    instance=1,
    name="DisarmCode",
    description="Write disarm code to deactivate alarm",
    presentValue=0,
    is_commandable = True,
).add_objects_to_application(device)



def check_code():
    code=(device["DisarmCode"].presentValue)
    if code == 1985:
        device["AlarmState"].presentValue = 0
    else:
        device["AlarmState"].presentValue = 1 # need to add this to prevent jsut setting alarm state to 0 I know it's Kludgey, but bacnet isnt' made for controlling alarms just reporting on them.
    # deferred(check_code)
    Timer(0.25, check_code).start()

deferred(check_code)

# run it
try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    stop()

