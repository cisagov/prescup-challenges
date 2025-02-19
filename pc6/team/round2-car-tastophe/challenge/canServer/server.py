import json
import time
import can
# from can.interfaces.udp_multicast import UdpMulticastBus
import devices
from apscheduler.schedulers.blocking import BlockingScheduler
import logging

logging.basicConfig()  
# Avoid overwhelming logs with misfires due to high schedule speed
logging.getLogger('apscheduler').setLevel(logging.ERROR)

DEBUG = False

interface = 'socketcan'
channel = 'vcan0'

# Really useful for debugging as requires no drivers or hardware
# Edit: For some reason, not installed by python-can on the server, so causes issues there
# if DEBUG:
#     interface = 'udp_multicast'
#     channel = UdpMulticastBus.DEFAULT_GROUP_IPv4

# Set up like this to easily turn off
devs = [
    devices.Brakes, 
    devices.Steering, 
    devices.unknown_02a, 
    devices.abs,
    devices.vcm, 
    devices.motor_rpm,
    devices.power_vcm,
    devices.unknown_1d5,
    devices.unknown_1f9,
    devices.unknown_215,
    devices.prox,
    devices.unknown_245,
    devices.cluster_display,
    devices.eyebrow,
    devices.frontWheels,
    devices.backWheels,
    devices.unknown_292,
    devices.unknown_2de,
    devices.steeringForce,
    devices.unknown_351,
    devices.unknown_354,
    devices.unknown_355,
    devices.bodyControl,
    devices.unknown_35d,
    devices.tpms,
    devices.prndl,
    devices.ACCompressor,
    devices.unknown_50d,
    devices.climatePower,
    devices.climateSet,
    devices.climateDisplay,
    devices.unknown_551,
    devices.parkingBrake,
    devices.batteryTemp,
    devices.unknown_5c0,
    devices.odometer,
    devices.unknown_5e3,
    devices.unknown_5e4,
    devices.monthDay,
    devices.unknown_5fb,
    devices.time,
    devices.lights,
    devices.headlights,
    devices.unknown_6f6  
]

logging.info(f"Loaded {len(devs)} devices")

with open('ac_status.json', 'w') as f:
    logging.info("Cleared ac_status.json")
    json.dump(devices.dynamicStatus, f)  # Clear it if it already exists
    
class dynamicCheck(can.Listener):
    badReads = 0
    
    def on_message_received(self, msg : can.Message):
        if msg.dlc != 8:
            logging.info(f"Ignored a malformed packet with id {msg.arbitration_id}")
            return  # Silently ignore malformed ac packets
        if msg.arbitration_id == 0x510:
            if msg.data[0] == 0:
                return  # No change
            devices.dynamicStatus["power"] = ((msg.data[3] >> 1) & 0b00111111)
            if devices.dynamicStatus["power"] > 0:
                devices.dynamicStatus["on"] = (msg.data[3] & 0b10000000) > 0
            logging.info(f"AC on and power set to {devices.dynamicStatus['on']} {devices.dynamicStatus['power']}")
        elif msg.arbitration_id == 0x54b:
            if msg.data[0] == 0 or not devices.dynamicStatus["on"]:
                return # No change or climate control off
            devices.dynamicStatus["displayOn1"] = msg.data[1]
            devices.dynamicStatus["displayOn2"] = msg.data[2]
            
            if msg.data[7] == 1:
                devices.dynamicStatus["userFanSpeed"] = msg.data[4]
            logging.info(f"AC display1/2 and fan set to {devices.dynamicStatus['displayOn1']} {devices.dynamicStatus['displayOn2']} {devices.dynamicStatus['userFanSpeed']}")
        elif msg.arbitration_id == 0x1ca:
            brakes = msg.data[0:4]
            brakes_are_bad = False

            for b in brakes:
                if int(b) > 120 or int(b) < 80:
                    brakes_are_bad = True
                        
            if brakes_are_bad and not devices.dynamicStatus["brakesHalted"]:
                dynamicCheck.badReads += 1
            elif dynamicCheck.badReads > 0 and not devices.dynamicStatus["brakesHalted"]:
                dynamicCheck.badReads -= 1
            
            if dynamicCheck.badReads % 10 == 0 and dynamicCheck.badReads != 0 and not devices.dynamicStatus["brakesHalted"]:
                logging.info(f"Currently at {dynamicCheck.badReads}/100")
            
            if dynamicCheck.badReads >= 100 and not devices.dynamicStatus["brakesHalted"]:
                devices.dynamicStatus["brakesHalted"] = True
                logging.info("Brakes halted")
            else: 
                return

        # If reached here, something changed, write it out
        with open('ac_status.json', 'w') as f:
            logging.info("Updated ac_status.json")
            json.dump(devices.dynamicStatus, f)
    
can_filters = [
    {"can_id": 0x1ca, "can_mask": 0x7FF},  # Filter for CAN ID
    {"can_id": 0x510, "can_mask": 0x7FF},
    {"can_id": 0x54b, "can_mask": 0x7FF},
]

def setupScheduler(sched : BlockingScheduler, dev):
    sched.add_job(dev.sendMessage, 'interval', seconds=dev.interval, max_instances=1, coalesce=True)

def serve():
    with can.Bus(channel=channel, interface=interface) as bus_1, \
                can.Bus(channel=channel, interface=interface, can_filters=can_filters) as log_bus:
        # register a callback on the logging bus that prints messages to the standard out
        if DEBUG:
            notifier = can.Notifier(bus_1, [can.Printer()])
        notifier = can.Notifier(log_bus, [dynamicCheck()])
        
        logging.info(f"Attached to {channel}/{interface}")

        # Setup each device
        mal = devices.malDev(bus_1)
        secret = devices.secretMessage(bus_1)
        scheduler = BlockingScheduler()
        setupScheduler(scheduler, mal)
        setupScheduler(scheduler, secret)

        logging.info(f"All device setup complete")

        for d in devs:
            dev = d(bus_1)
            setupScheduler(scheduler, dev)
        
        # Run until interrupted
        try:
            scheduler.start() # Let scheduler run
        except KeyboardInterrupt:
            logging.info('Ending server by interrupt!')
            scheduler.shutdown()

while True:
    try: 
        serve()
    except OSError as e:
        logging.warning("Failed to start due to missing vcan0. Waiting 30 seconds and trying again. Error was:" + str(e))
        time.sleep(30)
            
