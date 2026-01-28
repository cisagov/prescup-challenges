#!/usr/bin/env python3

import ipaddress
import logging
from os import getenv
import socket
import subprocess
import sys

from bacpypes.core import run, deferred, enable_sleeping, stop
from bacpypes.iocb import IOCB

from bacpypes.pdu import Address
from bacpypes.apdu import ReadPropertyRequest, ReadPropertyACK
from bacpypes.primitivedata import Unsigned, ObjectIdentifier

from bacpypes.app import BIPSimpleApplication
from bacpypes.object import get_datatype
from bacpypes.local.device import LocalDeviceObject
from bacpypes.task import RecurringTask, RecurringFunctionTask, FunctionTask

# Define structure for each light component
class LightPoint:
    def __init__(self, name, id, iocb=None):
        self.name = name
        self.id = id
        self.iocb = iocb

# Check that all of the lights in the lecture hall are either dimmed to 0 or turned off
# Note list includes all lights; ones that are ignored for grading a commented out
# ( (light name, id, iocb) (light dimmer name, id, iocb) )
lights = [
    # (LightPoint("Entry Lights", "binaryOutput:1", None), LightPoint("Entry Dimmer", "analogOutput:1", None)),
    (LightPoint("Lecture Room Overhead Lights", "binaryOutput:2", None), LightPoint("Lecture Room Dimming", "analogOutput:2", None)),
    # (LightPoint("Men's Bathroom Lights", "binaryOutput:3", None), None),
    # (LightPoint("Women's Bathroom Lights", "binaryOutput:4", None), None),
    # (LightPoint("Maintenance Room Light", "binaryOutput:5", None), None),
    # (LightPoint("Main Hallway Lights", "binaryOutput:6", None), None),
    (LightPoint("Lecture Room Front Stage Lights", "binaryOutput:7", None), LightPoint("Front Stage Dimming", "analogOutput:3", None)),
    (LightPoint("Lecture Room Aisle Lights", "binaryOutput:8", None), LightPoint("Aisle Lighting Dimming", "analogOutput:4", None)),
    (LightPoint("Lecture Room Rear Zone Lights", "binaryOutput:9", None), LightPoint("Rear Zone Dimming", "analogOutput:5", None)),
    (LightPoint("Accent/Presentation Lighting", "binaryOutput:10", None), LightPoint("Accent Lighting Dimming", "analogOutput:6", None)),
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

this_application = None

light_ip_address = socket.gethostbyname("lecturelights.pccc")

def get_nonlocal_ips():
    """
    Uses `ip -4 -o addr show` to list IPv4 addresses.
    Returns a list of non-local addresses (not 127.x.x.x).
    """
    try:
        output = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"],
            stderr=subprocess.STDOUT
        ).decode().strip()
    except Exception as e:
        logger.error("Failed to run `ip`: %s", e)
        return []

    ips = []
    for line in output.splitlines():
        parts = line.split()
        # ip -4 -o addr output looks like:
        # 2: eth0    inet 10.0.1.10/24 brd ...
        if "inet" in parts:
            idx = parts.index("inet")
            addr = parts[idx + 1]   # e.g. "10.0.1.10/24"
            ip = addr.split("/")[0]
            if not ip.startswith("127."):
                ips.append(ip)

    # Deduplicate while preserving order
    return list(dict.fromkeys(ips))

def get_correct_ip(goal, list_of_ips):
    goal_net = ipaddress.ip_network(f"{goal}/26", strict=False)
    for ip in list_of_ips:
        if ipaddress.ip_address(ip) in goal_net:
            return ip
    return None

def queueReads(addr, obj_id, prop_id):
    try:
        obj_id = ObjectIdentifier(obj_id).value
        if prop_id.isdigit():
            prop_id = int(prop_id)

        datatype = get_datatype(obj_id[0], prop_id)
        if not datatype:
            raise ValueError("invalid property for object type")

        # build a request
        request = ReadPropertyRequest(
            objectIdentifier=obj_id, propertyIdentifier=prop_id
        )
        request.pduDestination = Address(addr)

        # make an IOCB
        iocb = IOCB(request)

        # give it to the application
        deferred(this_application.request_io, iocb)
        
        # return the iocb so we can continue execution
        return iocb
    except Exception as error:
        logger.error(error)

def check_lights():
    global light_ip_address
    logger.info("Checking lights")
    for light, dimmer in lights:
        logger.info(f"Queuing light request for {light.name}")
        light.iocb = queueReads(light_ip_address, light.id, "presentValue")
        if dimmer is None:
            continue
        logger.info(f"Queuing dimmer request for {dimmer.name}")
        dimmer.iocb = queueReads(light_ip_address, dimmer.id, "presentValue")
    FunctionTask(waitForComplete, lights).install_task(delta=1)
    logger.info("Waiting on requests...")

def waitForComplete(lights):
    for light, dimmer in lights:
        if not light.iocb.wait(timeout=0.1):
            logger.info(f"Waiting on response for {light.name}...")
            FunctionTask(waitForComplete, lights).install_task(delta=1)
            return
        elif dimmer is not None and not dimmer.iocb.wait(timeout=0.1):
            logger.info(f"Waiting on response for {dimmer.name}...")
            FunctionTask(waitForComplete, lights).install_task(delta=1)
            return
    logger.info("All responses received")
    deferred(readResults, lights)
        
def readResults(iocbs):
    countLights = 0
    lastLight = ""
    for light, dimmer in lights:
        dark = False
        if dimmer is not None:
            dark = False
            if getValue(dimmer.iocb) is None:
                logger.error("Was unable to retrieve float value for a dimmer")
            else:
                dark = getValue(light.iocb) == "inactive" or getValue(dimmer.iocb) < 1.0
            logger.info(f"{light.name} is {'dark' if dark else 'bright'}: {getValue(light.iocb)} :: {getValue(dimmer.iocb)}")
        else:
            dark = getValue(light.iocb) == "inactive"
            logger.info(f"{light.name} is {'dark' if dark else 'bright'}: {getValue(light.iocb)}")
        
        if not dark:
            countLights += 1
            lastLight = light.name
    if countLights == 0:
        logger.info("All lights inactive or completely dimmed, awarding token")
        print(f"tokenLights: Success -- The lecture hall is in the dark")
    elif countLights == 1:
        print(f"tokenLights: Failed -- It must be pitch black and one light is left shining: {lastLight}")
    else:
        print(f"tokenLights: Failed -- There are still {countLights} lights left shining")
    deferred(stop)

def getValue(iocb):
    # do something for error/reject/abort
    if iocb.ioError:
        sys.stdout.write(str(iocb.ioError) + "\n")
    # do something for success
    elif iocb.ioResponse:
        apdu = iocb.ioResponse

        # should be an ack
        if not isinstance(apdu, ReadPropertyACK):
            logger.error("Response was not a ReadPropertyACK")
            return

        # find the datatype
        datatype = get_datatype(
            apdu.objectIdentifier[0], apdu.propertyIdentifier
        )
        
        if not datatype:
            raise TypeError("unknown datatype")

        value = apdu.propertyValue.cast_out(datatype)

        return value
    return None
        
def main():
    global this_application

    # make a device object
    device = LocalDeviceObject(
        objectName="grader",
        objectIdentifier=599,
        maxApduLengthAccepted=1024,
        segmentationSupported="segmentedBoth",
        vendorIdentifier=15
    )

    correct_ip = get_correct_ip(light_ip_address, get_nonlocal_ips())
    
    logger.info(f"Found Light IP Address as {correct_ip}")
    
    # make a simple application
    this_application = BIPSimpleApplication(device, f"{correct_ip}/0")

    deferred(check_lights)

    # enable sleeping will help with threads
    enable_sleeping()

    run()


if __name__ == "__main__":
    main()