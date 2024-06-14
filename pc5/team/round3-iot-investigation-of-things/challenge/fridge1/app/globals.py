#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, json, datetime
from threading import Lock
from app.functions import load_config, update_config

global basedir
basedir =  os.path.abspath(os.path.dirname(__file__))

global config_fp
config_fp = basedir + "/config.yaml"

global config
config = load_config()

global config_lock
config_lock = Lock()

global cc_url
cc_url = "http://10.4.4.250/store"

global num_logs_to_send
num_logs_to_send = 3

global log_id_tracker
log_id_tracker = []

global logs_to_delete
logs_to_delete = list()

global shared_file
shared_file = "/shared/fridge1.status"

global temp_counter
temp_counter = 0

global config_ranges
config_ranges = {
    "temperature_values":{
        'f': {
            '0':[32,33],
            '1':[33,34],
            '2':[34,35],
            '3':[35,36],
            '4':[36,37],
            '5':[37,38]
        },
        'c': {
            '0':[0,1],
            '1':[1,2],
            '2':[2,3],
            '3':[3,4],
            '4':[4,5],
            '5':[5,6]
        },
    },
    "status":["good", "failing"]
}

global update_server
update_server = "http://179.77.202.10"

global update_server_port
update_server_port = '28572'

global update_status
update_status = "pass"

next_update = datetime.datetime.now() + datetime.timedelta(weeks=1)
config['device_info']['next_update'] = next_update.strftime("%Y-%m-%d %H:%M:%S")
update_config()

global keys
keys = {
    "previous":"",
    "current":"a61Z5A"
}

## For rate limiting POST requests
global timeout
timeout = {
    "status":False,
    "timer": datetime.timedelta(seconds=10),
    "end_time": None
}
