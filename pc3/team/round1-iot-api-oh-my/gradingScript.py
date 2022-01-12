#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import json
import os
import logging

logging.basicConfig(format='%(asctime)s  %(levelname)s  %(message)s', level=logging.INFO, datefmt='%m/%d/%Y %I:%M:%S %p')

key_location = "./keys"
device_location = "./devices"

device_files = os.listdir(device_location)

results = {}

len_keys = len(open(key_location, 'r').readlines())
logging.info(f"There are {len_keys} in the keys file")

if  len_keys > 1:
    results['Authentication'] = "Success -- You received an API key from the server"
else:
    results['Authentication'] = "Failure -- You have not received an API key from the server"

for device_file in device_files:
    with open(f"{device_location}/{device_file}", 'r') as df:
        device_status = json.load(df)
    logging.info(f"{device_file} Status: {device_status}")
    try:
        if not device_status['power']:
            results['Camera'] = "Success -- Camera power has successfully been turned off"
        else:
            results['Camera'] = "Failure -- The camera is still turned on."
    except KeyError:
        if device_status['status'] == 'unlocked':
            results['Door'] = "Success -- Door was successfully unlocked"
        else:
            results['Door'] = "Failure -- The door is still locked"

for key, value in results.items():
    print(key, ' : ', value)

