import logging
from os import getenv
import os
import random
import sys
import time
from bacpypes.core import run, stop
from bacpypes.app import BIPSimpleApplication, Error, ExecutionError
from bacpypes.local.device import LocalDeviceObject
from bacpypes.object import BinaryValueObject, BinaryInputObject, BinaryOutputObject
from bacpypes.object import AnalogValueObject, AnalogOutputObject, AnalogInputObject
from bacpypes.object import MultiStateInputObject, MultiStateOutputObject, MultiStateValueObject
from bacpypes.object import CharacterStringValueObject
from bacpypes.service.device import WhoIsIAmServices
from bacpypes.task import TaskManager, FunctionTask
from bacpypes.basetypes import EngineeringUnits
import socket
import yaml
from bacpypes.primitivedata import Boolean, CharacterString

import re

from temp_monitoring import setSecurityHost, FireMode, HVACDisable, HighTempAlarmThreshold, SmokeDamper, launchHTTPListener, saveSecurityDoor, securityInstance, serverDoorName, getSecurityDoor

import resolver_client

CUSTOM_CLASS_REGISTRY = {
    "HighTempAlarmThreshold": HighTempAlarmThreshold,
    "SmokeDamper": SmokeDamper,
    "HVACDisable": HVACDisable,
    "FireMode": FireMode,
}

def customClassLookup(class_name):
    cls = CUSTOM_CLASS_REGISTRY.get(class_name)
    if not cls:
        raise ValueError(f"Unknown custom class: {class_name}")
    return cls

def create_abbreviation(phrase):
    # Extract words that start with an alphabetic character
    words = re.findall(r'\b[a-zA-Z]', phrase)
    return ''.join(words).upper()

logging.basicConfig(level=logging.INFO)

globalTasks = TaskManager()

class SampleApplication(BIPSimpleApplication, WhoIsIAmServices):

    def __init__(self, device, address):
        BIPSimpleApplication.__init__(self, device, address)
        WhoIsIAmServices.__init__(self)

class RandomBinaryInputObject(BinaryInputObject):
    def __init__(self, delay=60, **kwargs):
        super().__init__(**kwargs)
        self._previous_value = self.presentValue
        self._task = None
        self._delay = delay
        self._start_random_updates()

    def _start_random_updates(self):
        def update_value():
            new_value = random.choice([0, 1])

            if self.presentValue != new_value:
                self._previous_value = self.presentValue
                self.presentValue = new_value
                logging.info(f"{self.objectName}: presentValue -> {new_value}")

                # Notify subscribers if value changed
                self._cov_notify()

            # Reschedule
            # self._task.install_task(FunctionTask(update_value), delta= interval * 1000)
            self._task.install_task(delta = self._delay)
        self._task = FunctionTask(update_value)
        self._task.install_task(delta = self._delay)

    def _cov_notify(self):
        if hasattr(self, '_cov_subscriptions') and self._cov_subscriptions:
            self._cov_change('presentValue')

class RandomAnalogInputObject(AnalogInputObject):
    def __init__(self, delay=60, randomMin=0, randomMax=100, randomAmount=1, **kwargs):
        super().__init__(**kwargs)
        self._previous_value = self.presentValue
        self._task = None
        self._delay = delay
        self._randomMin = float(randomMin)
        self._randomMax = float(randomMax)
        self._randomAmount = float(randomAmount)
        self._start_random_updates()

    def _start_random_updates(self):
        def update_value():
            new_value = self._previous_value + round(random.uniform(-self._randomAmount, self._randomAmount), 2)

            if new_value < self._randomMin:
                new_value = self._randomMin
            elif new_value > self._randomMax:
                new_value = self._randomMax

            if self.presentValue != new_value:
                self._previous_value = self.presentValue
                self.presentValue = new_value
                logging.info(f"{self.objectName}: presentValue -> {new_value}")

                # Notify subscribers if value changed
                self._cov_notify()

            # Reschedule
            # self._task.install_task(FunctionTask(update_value), delta= interval * 1000)
            self._task.install_task(delta = self._delay)
        self._task = FunctionTask(update_value)
        self._task.install_task(delta = self._delay)

    def _cov_notify(self):
        if hasattr(self, '_cov_subscriptions') and self._cov_subscriptions:
            self._cov_change('presentValue')

# I'm like 99% sure it does this for Inputs after some testing, but ChatGPT said no. Since I already made it, I left it. 
def denyWrite(self, property, value, arrayIndex=None, priority=None, direct=False):
    raise ExecutionError(errorClass='property', errorCode='writeAccessDenied')

def readBinaryArgs(object):
    args = {
        "objectIdentifier":(object["type"], int(object['instance'])),
        "objectName": object["name"],
        "presentValue": "inactive",  # off by default, changed later if applicable
        "statusFlags": [0, 0, 0, 0],
        "eventState": "normal",
        "outOfService": False
    }
    
    if "Input" in object["type"]:
        classType = BinaryInputObject
        if object["state"]["type"] == "random":
            classType = RandomBinaryInputObject
    elif "Output" in object["type"]:
        classType = BinaryOutputObject
    else:
        classType = BinaryValueObject
    
    # A little messy with all this feature creep, but overwrite above class with custom
    if object["state"]["type"] == "custom":
        classType = customClassLookup(object["state"]["class"])
    
    try:
        args["presentValue"] = "active" if object["state"]["value"] == 1 else "inactive"
    except:
        logging.info("Default value not set - assuming false")
    
    return (classType, args)

def readAnalogArgs(object):
    args = {
        "objectIdentifier":(object["type"], int(object['instance'])),
        "objectName": object["name"],
        "presentValue": 1.0,  # 1.0 by default, changed later if applicable
        "statusFlags": [0, 0, 0, 0],
        "eventState": "normal",
        "outOfService": False,
        "units": "percent"  # default, changed later if applicable
    }
    
    if "Input" in object["type"]:
        classType = AnalogInputObject
        if object["state"]["type"] == "random":
            classType = RandomAnalogInputObject
            args["randomMin"] = float(object["state"]["randomMin"])
            args["randomMax"] = float(object["state"]["randomMax"])
            args["randomAmount"] = float(object["state"]["randomAmount"])
            args["delay"] = int(object["state"]["delay"])
    elif "Output" in object["type"]:
        classType = AnalogOutputObject
    else:
        classType = AnalogValueObject
    
    # A little messy with all this feature creep, but overwrite above class with custom
    if object["state"]["type"] == "custom":
        classType = customClassLookup(object["state"]["class"])
    
    try:
        args["presentValue"] = float(object["state"]["value"])
    except:
        logging.info("Default value not set correctly - using 1.0")
    
    try:    
        args["units"] = object["state"]["units"]
    except:
        logging.info("Default value not set correctly - using percent")
    
    return (classType, args)

def readMultistateArgs(object):
    args = {
        "objectIdentifier":(object["type"], int(object['instance'])),
        "objectName": object["name"],
        "presentValue": 0,  # 0 by default, should be changed later (0 represents error)
        "statusFlags": [0, 0, 0, 0],
        "eventState": "normal",
        "outOfService": False,
        "stateText": ["idle", "active", "fault", "manual override"]
    }
    
    if "Input" in object["type"]:
        classType = MultiStateInputObject
        if object["state"]["type"] == "random":
            logging.info("Random multistate input not yet implemented, will be constant")
    elif "Output" in object["type"]:
        classType = MultiStateOutputObject
    else:
        classType = MultiStateValueObject
    
    # A little messy with all this feature creep, but overwrite above class with custom
    if object["state"]["type"] == "custom":
        classType = customClassLookup(object["state"]["class"])
    
    try:
        args["presentValue"] = int(object["state"]["value"])
    except:
        logging.info("Default value not set correctly - using 0 for error")
    
    try:    
        args["stateText"] = list(object["states"].values())
    except:
        logging.error("Could not read the list of possible states, using default states")
    
    args["numberOfStates"] = len(args["stateText"])

    return (classType, args)

def createObject(object, deviceAbbreviation):
    if "binary" in object["type"]:
        classType, args = readBinaryArgs(object)
    elif "analog" in object["type"]:
        classType, args = readAnalogArgs(object)
    elif "multiState" in object["type"]:
        classType, args = readMultistateArgs(object)
    else:
        logging.error(f"Unknown type - {object['type']}")
        exit(-1)

    logging.info(f"Creating {object["type"]}:{object['instance']} - {object['name']}")
    
    if object["state"]["type"] == "random":
        try:
            args["delay"] = int(object["state"]["delay"])
            logging.info(f"Using delay of {args["delay"]} seconds")
        except:
            logging.info("Using default delay of 60 seconds")
    
    args["objectName"] = f"{deviceAbbreviation} - {args["objectName"]}"

    newObject = classType(**args)

    try:
        if not object["state"]["mutable"]:
            newObject.WriteProperty = denyWrite
            logging.info("Object is immutable, changed write function to error message")
    except:
        logging.info("Mutable setting not found - assuming mutable")

    return newObject

def main():
    try:
        instance = int(getenv("instance"))
    except ValueError:
        logging.error("The instance environment variable must be a number")
        exit(-1)

    if instance is None:
        logging.error("No device instance is defined!")
        exit(-1)
    logging.info(f"Looking for config for device {instance}")

    # Load config
    config = None
    with open("config.yaml", "r") as file:
        config = yaml.safe_load(file)

    deviceConfig = None
    for d in config['devices']:
        if d["instance"] == instance:
            deviceConfig = d
    
    if deviceConfig is None:
        logging.error(f"Could not find device {instance} in config!")
        exit(-1)

    logging.info(f"Found config for {instance}: {deviceConfig['name']}")

    # Device configuration
    device = LocalDeviceObject(
        objectName=deviceConfig["name"],
        objectIdentifier=instance,
        maxApduLengthAccepted=1024,
        segmentationSupported="segmentedBoth",
        vendorIdentifier=999
    )
    
    for attempt in range(1, 11):
        try:
            ips = resolver_client.get_nonlocal_ips()
            resolver_client.register_until_ok(ips[0], ips[1], os.getenv("hostname"))
            break
        except IndexError:
            logging.warning("IP list not ready (attempt %d/10), retrying in 5s", attempt)
        except Exception as e:
            logging.error("Failed to register IPs (attempt %d/10):\n%s", attempt, e)
        time.sleep(5)
    else:
        logging.error("Giving up after 10 attempts to retrieve and register IPs. Something is wrong with the network interfaces (give it a recycle).")
        exit(-1)

    all_hosts = resolver_client.wait_for_complete_list()

    my_ip_info = all_hosts[os.getenv("hostname")]
    # Also set the private IP for security.pccc
    setSecurityHost(all_hosts["security.pccc"]["platform_net"])
    
    # BACnet/IP settings
    this_address = my_ip_info["engineering_net"]
    this_port = 47808
    # For some reason, doing ip:port/0 did not work like the documentation suggests, 
    # but default port is already 47808. Note also that 0.0.0.0 suggested by ChatGPT also does not work
    # Netmask is /0 so the broadcast address is calculated as 255.255.255.255 
    logging.info(f"Setting device up on {this_address}:{this_port}/0")
    application = SampleApplication(device, f"{this_address}/0")

    abbrev = create_abbreviation(deviceConfig["name"])

    for object in deviceConfig["objects"]:
        logging.info(f"Loading object {object['type']}:{object['instance']} - '{object['name']}' ...")
        new = createObject(object, abbrev)
        if instance == securityInstance and object['name'] == serverDoorName:
            logging.info("Found and saving security door for server")
            saveSecurityDoor(new)
        application.add_object(new)
    
    # Add a hidden flag object
    tokenInstance = getenv("tokenInstance")
    token = getenv("tokenInObject")

    if tokenInstance is None:
        logging.error("The environment variable tokenInstance is not set!")
        exit(-1)
    elif instance == int(tokenInstance):
        if token is None:
            logging.error(f"In instance {tokenInstance}, the tokenInObject env should be present but is not set.")
            exit(-1)
        tokenObj = CharacterStringValueObject(
            objectIdentifier=("characterstringValue", 1),
            objectName="token",
            presentValue=token
        )
        application.add_object(tokenObj)
        logging.info(f"Added {token} in characterStringValue:1 - 'token' ...")

    if instance == securityInstance:
        if getSecurityDoor() is None:
            logging.error("securityDoor was not set!!")
            exit(-1)
        launchHTTPListener()
        
    try:
        run()  
    except KeyboardInterrupt:
        stop()    

if __name__ == '__main__':
    main()
