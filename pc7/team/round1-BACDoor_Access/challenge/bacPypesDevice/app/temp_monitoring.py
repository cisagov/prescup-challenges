from http.server import BaseHTTPRequestHandler, HTTPServer
from os import getenv
import threading
from urllib.parse import urlparse, parse_qs
import logging
import requests
from bacpypes.object import BinaryValueObject, BinaryInputObject, BinaryOutputObject
from bacpypes.object import AnalogValueObject, AnalogOutputObject, AnalogInputObject
from bacpypes.object import MultiStateInputObject, MultiStateOutputObject, MultiStateValueObject
from bacpypes.core import deferred

logging.basicConfig(level=logging.DEBUG)

# They need to (order doesn't matter):
# 1. Change the temp alert, so the server room thinks its hot. Set <= 80
# 2. Enable the fire test mode
# 3. The smoke damper override needs to be enabled
# 4. Disable HVAC
# Catastrophic failure, door opens for emergency services

# The door controller hosts the below HTTP server.
# Item 1 is in the server device; will send a request to "/tempChanged?temp=x" when changed. 
# Item 2, 3, and 4 in the fire safety device; will send a request to "/fireTest?mode=x", "/smokeDamper", "/hvacDisabled" when done
# "/smokeDamperReset", and "/hvacDisabledReset" will reset them if they change them back to the incorrect values

securityDoor = None
securityInstance = 2201
serverDoorName = "Server Room Door Lock"

tempLimit = 89.6
fireMode = 1
smokeDamper = False
hvacDisable = False

# Server configuration
# HOST = getenv('securitydoor_ip') # Now set when called by thread
HOST = ""
PORT = 8080

def setSecurityHost(ip):
    global HOST
    HOST = ip

def saveSecurityDoor(val):
    global securityDoor
    securityDoor = val

def getSecurityDoor():
    global securityDoor
    if securityDoor is None:
        logging.error("securityDoor was not set!!")
        exit(-1)
    return securityDoor

# Listens for an http request on a private network with the server room temp monitor
# When request is received, changes server door to unlocked.
# Simulates having a physical serial connection between the sensor and door
def setDoorOpen():
    # deferred(getSecurityDoor().WriteProperty, "presentValue", "inactive")
    getSecurityDoor().presentValue = "inactive"
    logging.info("Opening security door")

# Handler for temp changer
class HighTempAlarmThreshold(AnalogOutputObject):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def WriteProperty(self, property, value, arrayIndex=None, priority=None, direct=False):
        if property == "presentValue":
            try:
                logging.info(f"Sending request to http://{HOST}:{PORT}/tempChanged?temp={value}")
                response = requests.get(f"http://{HOST}:{PORT}/tempChanged", params={"temp": value})
                response.raise_for_status()
            except Exception as e:
                logging.error(f"Error notifying server of temperature change: {e}")
        super().WriteProperty(property, value, arrayIndex, priority, direct)   

# Handler for fire test mode
class FireMode(MultiStateOutputObject):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def WriteProperty(self, property, value, arrayIndex=None, priority=None, direct=False):
        if property == "presentValue":
            try:
                logging.info(f"Sending request to http://{HOST}:{PORT}/fireTest?mode={value}")
                response = requests.get(f"http://{HOST}:{PORT}/fireTest", params={"mode": value})
                response.raise_for_status()
            except Exception as e:
                logging.error(f"Error notifying server of fire mode change: {e}")
        super().WriteProperty(property, value, arrayIndex, priority, direct)   

# Handler for smoke damper
class SmokeDamper(BinaryValueObject):
    def __init__(self, **kwargs):
        self._setEndpoint = "smokeDamper"
        self._disableEndpoint = "smokeDamperReset"
        super().__init__(**kwargs)
    
    def WriteProperty(self, property, value, arrayIndex=None, priority=None, direct=False):
        if property == "presentValue":
            try:
                if value == "active":
                    url = f"http://{HOST}:{PORT}/{self._setEndpoint}"
                elif value == "inactive":
                    url = f"http://{HOST}:{PORT}/{self._disableEndpoint}"
                logging.info(f"Sending request to {url}")
                response = requests.get(url)
                response.raise_for_status()
            except Exception as e:
                logging.error(f"Error notifying server of smoke damper change: {e}")
        super().WriteProperty(property, value, arrayIndex, priority, direct)

# Handler for hvac disable
class HVACDisable(BinaryOutputObject):
    def __init__(self, **kwargs):
        self._setEndpoint = "hvacDisabled"
        self._disableEndpoint = "hvacDisabledReset"
        super().__init__(**kwargs)
    
    def WriteProperty(self, property, value, arrayIndex=None, priority=None, direct=False):
        if property == "presentValue":
            try:
                if value == "active":
                    url = f"http://{HOST}:{PORT}/{self._setEndpoint}"
                elif value == "inactive":
                    url = f"http://{HOST}:{PORT}/{self._disableEndpoint}"
                logging.info(f"Sending request to {url}")
                response = requests.get(url)
                response.raise_for_status()
            except Exception as e:
                logging.error(f"Error notifying server of hvac disable change: {e}")
        super().WriteProperty(property, value, arrayIndex, priority, direct)

tempLimit = 89.0
fireMode = 1
smokeDamper = False
hvacDisable = False

class RequestHandler(BaseHTTPRequestHandler):
    
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
    
    def do_GET(self):
        global tempLimit, fireMode, smokeDamper, hvacDisable
        # Parse the URL
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        
        if parsed.path == "/tempChanged":
            tempLimit = float(query.get('temp', [None])[0])
            logging.info(f"Temp limit changed to {tempLimit}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Temp set\n")
        elif parsed.path == "/fireTest":
            fireMode = int(query.get('mode', [None])[0])
            logging.info(f"Fire mode changed to {fireMode}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Firemode set\n")
        elif parsed.path == "/smokeDamper":
            smokeDamper = True
            logging.info(f"Smoke damper changed to True")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SmokeDamper set\n")
        elif parsed.path == "/hvacDisabled":
            hvacDisable = True
            logging.info(f"HVAC disable changed to True")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"HVAC set\n")
        elif parsed.path == "/smokeDamperReset":
            smokeDamper = False
            logging.info(f"Smoke damper changed to False")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SmokeDamper unset\n")
        elif parsed.path == "/hvacDisabledReset":
            hvacDisable = False
            logging.info(f"HVAC disable changed to False")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"HVAC unset\n")
        else:
            logging.error(f"Bad request to {self.path}")
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found\n")
        
        if tempLimit <= 80.0 and (fireMode == 2) and smokeDamper and hvacDisable:
            logging.info("Conditions met, call setDoorOpen")
            setDoorOpen()

def start_http_server():
    server = HTTPServer((HOST, 8080), RequestHandler)
    print("HTTP server listening on port 8080")
    server.serve_forever()

# Start HTTP server in background thread
def launchHTTPListener():
    threading.Thread(target=start_http_server, daemon=True).start()