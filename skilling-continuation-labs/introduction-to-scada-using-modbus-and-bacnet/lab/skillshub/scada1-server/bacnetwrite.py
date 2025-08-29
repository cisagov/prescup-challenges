#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import BAC0
import json
import time

local_ip = "10.7.7.10/24"
poll_interval = 2  # seconds between polls

devices = {
    "GarageDoor": {
        "ip": "10.3.3.101",
        "points": {"DoorState": "binaryValue 1"}
    },
    "Thermostat": {
        "ip": "10.3.3.102",
        "points": {
        "RoomTemp": "analogInput 1",
        "SetTemp": "analogValue 1",
        "SystemMode": "multiStateValue 1"
        }
    },
    "AlarmPanel": {
        "ip": "10.3.3.103",
        "points": {
        "AlarmState": "binaryValue 1",
        "DisarmCode": "analogValue 1"
        }
    }   
}

def poll_devices(bacnet):
    results = {}
    for dev, info in devices.items():
        results[dev] = {}
        for label, obj in info["points"].items():
            try:
                val = bacnet.read(f"{info['ip']} {obj} presentValue")
                results[dev][label] = val
            except Exception as e:
                results[dev][label] = f"error: {e}"
    return results

def main():
    bacnet = BAC0.connect(ip=local_ip)
    last_results = None

    while True:
        results = poll_devices(bacnet)

    # Only write if results changed
        if results != last_results:
            with open("/var/www/html/scadaweb/bacnet_status.json", "w") as f:
                json.dump(results, f, indent=2)
            print(f"[{time.strftime('%H:%M:%S')}] Updated bacnet_status.json")
            last_results = results

    time.sleep(poll_interval)

if __name__ == "__main__":
    main()
