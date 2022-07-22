
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


## Run this solution script with `python3 ./solution.py`

import socket
import binascii

# counted header length by looking at pcap to determine how many characters are sent for the header
header_len = 210

# messages and their response size are taken from the pcap. Use the requests/responses in the pcap to determine these numbers/messages

register_message = b'\x00\x80{"byteorder": "little", "content-type": "text/json", "content-encoding": "utf-8", "content-length": 22, "app-key": "1234567890"}{"action": "register"}'
register_response_size = 100

get_message = b'{"byteorder": "little", "content-type": "text/json", "content-encoding": "utf-8", "content-length": 17, "app-key": "APPKEY"}{"action": "get"}'
get_response_size = 184

unlock_message = b'{"byteorder": "little", "content-type": "text/json", "content-encoding": "utf-8", "content-length": 203, "app-key": "APPKEY"}{"action": "update", "update": {"devicetype": "lock", "deviceid": "LOCKID", "devicename": "main door lock", "status": "unlocked", "timestamp": "2020-01-03 10:39:20.341234"}}'
unlock_response_size = 80

camera_standby_message = b'{"byteorder": "little", "content-type": "text/json", "content-encoding": "utf-8", "content-length": 229, "app-key": "APPKEY"}{"action": "update", "update": {"devicetype": "camera", "deviceid": "CAMID", "devicename": "front parking lot camera", "power": true, "status": "standby", "timestamp": "2020-01-05 11:21:42.768352"}}'
camera_standby_response_size = 92

camera_power_message = b'{"byteorder": "little", "content-type": "text/json", "content-encoding": "utf-8", "content-length": 230, "app-key": "APPKEY"}{"action": "update", "update": {"devicetype": "camera", "deviceid": "CAMID", "devicename": "front parking lot camera", "power": false, "status": "standby", "timestamp": "2020-01-05 11:21:42.768352"}}'
camera_power_response_size = 64


# define the address to connect to
## You may need to change the hostname from 'localhost' to whatever the hostname/IPaddress is running the API in your case
server_address = (socket.gethostbyname('localhost'), 12345) 


## Register with the API and get an API KEY
try:
    # connect to socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to %s port %s" % server_address)
    sock.connect(server_address)
    # send hex encoded data to the socket server
    print("Sending register")
    sock.sendall(binascii.hexlify(register_message))
    
    # receive data -- keeping track of how much data is expected and how much has been received so far. 
    rec_data = b""
    received = 0
    expected = header_len + register_response_size
    while received < expected:
        data = sock.recv(1)
        received += len(data)
        rec_data += data
    
    # decode hex message
    message = binascii.unhexlify(rec_data[4:])
    print(f"Received message: {message}")

# close socket
finally:
    print("Closing")
    sock.close()
APP_KEY = message[-38:-2].decode()
print(f"key: {APP_KEY}")


get_message = b'\x00\x9a' + bytes(get_message.decode().replace("APPKEY", APP_KEY), "UTF-8")
print(get_message)

## Get the devices out of the API
## there should only be 2 devices
## Device order depends on the UUID of the devices 
try:
    print("Sending get devices")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    sock.sendall(binascii.hexlify(get_message))
    rec_data = b""
    received = 0
    expected = header_len + get_response_size
    while received < expected:
        data = sock.recv(1)
        received += len(data)
        rec_data += data
    message = binascii.unhexlify(rec_data[4:])
    print(f"Received message: {message}")

finally:
    print("Closing")
    sock.close()

## lock and camera IDs may be swapped -- try it the other way if it doesn't work the first time 
print(f"Devices: {message[114:-1]}")
lock_id = message[116:152].decode()
print(f"lock: {lock_id}")
cam_id = message[156:192].decode() 
print(f"camera: {cam_id}")


## Unlock the door 
unlock_message = b'\x00\x9b' + bytes(unlock_message.decode().replace("APPKEY", APP_KEY).replace("LOCKID", lock_id), "UTF-8")
print(unlock_message)
try:
    print("Sending unlock door")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    sock.sendall(binascii.hexlify(unlock_message))
    rec_data = b""
    received = 0
    expected = header_len + unlock_response_size
    while received < expected:
        data = sock.recv(1)
        received += len(data)
        rec_data += data
    message = binascii.unhexlify(rec_data[4:])
    print(f"Received message: {message}")

finally:
    print("Closing")
    sock.close()

## Put camera in standby mode
camera_standby_message = b'\x00\x9b' + bytes(camera_standby_message.decode().replace("APPKEY", APP_KEY).replace("CAMID", cam_id), "UTF-8")
print(camera_standby_message)
try:
    print("Sending camera standby")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    sock.sendall(binascii.hexlify(camera_standby_message))
    rec_data = b""
    received = 0
    expected = header_len + camera_standby_response_size
    while received < expected:
        data = sock.recv(1)
        received += len(data)
        rec_data += data
    message = binascii.unhexlify(rec_data[4:])
    print(f"Received message: {message}")

finally:
    print("Closing")
    sock.close()


## Power off camera
camera_power_message = b'\x00\x9b' + bytes(camera_power_message.decode().replace("APPKEY", APP_KEY).replace("CAMID", cam_id), "UTF-8")
print(camera_power_message)
try:
    print("Sending camera power off")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    sock.sendall(binascii.hexlify(camera_power_message))
    rec_data = b""
    received = 0
    expected = header_len + camera_power_response_size
    while received < expected:
        data = sock.recv(1)
        received += len(data)
        rec_data += data
    message = binascii.unhexlify(rec_data[4:])
    print(f"Received message: {message}")

finally:
    print("Closing")
    sock.close()
