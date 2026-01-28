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

# Reusing the LightPoint, but the object is now a door, not a light
# The code is otherwise very similar, so just modifying logging statements, no dimmer, and token logic

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
    (LightPoint("Lab 301 Door Lock", "binaryOutput:1", None)),
    (LightPoint("Server Room Door Lock", "binaryInput:4", None))
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

this_application = None

light_ip_address = socket.gethostbyname("security.pccc")

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
        logger.error(f"queueReads with {addr} {obj_id} {prop_id}")
        exit(-1)

def check_lights():
    global light_ip_address
    logger.info("Checking door")
    for light in lights:
        logger.info(f"Queuing request for {light.name}")
        light.iocb = queueReads(light_ip_address, light.id, "presentValue")
    FunctionTask(waitForComplete, lights).install_task(delta=1)
    logger.info("Waiting on requests...")

def waitForComplete(lights):
    for light in lights:
        if not light.iocb.wait(timeout=0.1):
            logger.info(f"Waiting on response for {light.name}...")
            FunctionTask(waitForComplete, lights).install_task(delta=1)
            return
    logger.info("All responses received")
    deferred(readResults, lights)
        
def readResults(lights):
    labLocked = True
    labLocked = getValue(lights[0].iocb) == "active"
    logger.info(f"{lights[0].name} is {"locked" if labLocked else "open"}: {getValue(lights[0].iocb)}")
        
    if not labLocked:
        logger.info("Lab door is unlocked, awarding token")
        print(f"tokenLabdoor: Success -- Unlocked the lab door")
    else:
        print(f"tokenLabdoor: Failed -- You jiggle the lab door... Locked... Back to the musty maintenance room.")
    
    serverLocked = True
    serverLocked = getValue(lights[1].iocb) == "active"
    logger.info(f"{lights[1].name} is {"locked" if serverLocked else "open"}: {getValue(lights[1].iocb)}")
        
    if not serverLocked:
        logger.info("Server room door is unlocked, awarding token")
        print(f"tokenServerdoor: Success -- Unlocked the server door")
    else:
        print(f"tokenServerdoor: Failed -- You jiggle the server door... Locked... Back to the musty maintenance room.")
        
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
    
    logger.info(f"Found Door IP Address as {correct_ip}")
    
    # make a simple application
    this_application = BIPSimpleApplication(device, f"{correct_ip}/0")

    deferred(check_lights)

    # enable sleeping will help with threads
    enable_sleeping()

    run()


if __name__ == "__main__":
    main()