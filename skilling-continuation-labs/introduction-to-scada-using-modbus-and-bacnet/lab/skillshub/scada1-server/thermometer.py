
# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from time import sleep
from BAC0 import lite
from BAC0.core.devices.local.models import analog_input, analog_value
from BAC0.core.devices.local.object import ObjectFactory
from bacpypes.object import MultiStateValueObject
from bacpypes.core import run, stop
from bacpypes.primitivedata import Real

# device settings
dev_ip = "10.3.3.102/24"
dev_port = 47808
dev_id = 2002

device = lite(ip=dev_ip, port=dev_port, deviceId=dev_id)

# Room temperature (read-only)
analog_input(
instance=1,
name="RoomTemperature",
description="Current room temperature",
presentValue=Real(72.5),
properties={"units": "degreesFahrenheit"},
).add_objects_to_application(device)

# Setpoint temperature (writable)
analog_value(
instance=1,
name="SetTemp",
description="Desired temperature",
presentValue=Real(70.0),
is_commandable=True,
properties={"units": "degreesFahrenheit"},
).add_objects_to_application(device)

# System mode (Off=1, Heat=2, Cool=3, Fan=4)
system_mode = ObjectFactory(
MultiStateValueObject,
1,
"SystemMode",
properties={
"numberOfStates": 4,
"stateText": ["Off", "Heat", "Cool", "Fan"],
"presentValue": 1,
},
description="System mode selector",
)
system_mode.is_commandable = True
system_mode.add_objects_to_application(device)

try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    stop()

