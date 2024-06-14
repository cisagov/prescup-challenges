
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#! /bin/python3
import socket
import datetime
import threading
import os
from time import sleep

# Create a socket and connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("10.5.5.5", 9999))

response_messages = []

def receive_messages(stop_event):
    while True:
        response = client.recv(4096).decode()

        if "Game over" in response:
            print(response)
            stop_event.set()
            client.close()
            break
        elif response == "request_time":
            print("Sending current time...")
            current_time = datetime.datetime.now()
            current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            client.send(f"{current_time}".encode())
        else:
            print(response)
            
def send_messages(stop_event):
        while True:
            sleep(1)
            print("Rooms available: time, treasure, key, elf, north, east, west")
            user_input = input("Type in either room name or action (quit to exit):\n").lower()
            if user_input == "quit":
                client.send(user_input.encode())
                stop_event.set()
                break
            client.send(user_input.encode())

receive_stop_event = threading.Event()
receive_thread = threading.Thread(target=receive_messages, args=(receive_stop_event, ))
receive_thread.daemon = True
receive_thread.start()

send_stop_event = threading.Event()
send_thread = threading.Thread(target=send_messages, args=(send_stop_event, ))
send_thread.daemon = True
send_thread.start()

try:
    while not receive_stop_event.is_set() and send_stop_event.is_set():
        pass
    receive_thread.join()
    send_thread.join()
except KeyboardInterrupt:
    receive_thread.join()
    send_thread.join()
    client.close()

