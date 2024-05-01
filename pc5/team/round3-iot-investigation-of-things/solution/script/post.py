#!/usr/bin/python3

import os, sys, requests, json

data = {
    "update_key": **update key**,
    "server_url":"179.77.202.10",
    "server_port":"28572",
    "device_endpoint":"fridge"
}

resp2 = requests.post("http://10.3.3.40/update-server-pointer",json=data, headers={"Content-Type":"application/json"})

rec = resp2.content.decode("utf-8")

print(json.dumps(json.loads(rec),indent=2))
