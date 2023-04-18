#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import socket,socketserver, subprocess, json, math, time, os, hashlib, datetime, sys, random
from datetime import datetime
import asyncore, collections, logging
import threading, time, sys, signal, select
from _thread import *


port=33146
token="d5a412735965"
#keyvar = subprocess.run("vmware-rpctool 'info-get guestinfo.k3'",shell=True, capture_output=True).stdout.decode('utf-8').strip('\n') - not used in final version

class handler_TCPServer(socketserver.StreamRequestHandler):       
    def handle(self):
        flag = token
        key = str(random.randint(100000,999999)).zfill(6)
        ## get current index to use & count of incorrect attempts 
        ## with open("keyInfo.txt",'r') as f:
        ##    tmp = f.read()                  # file to maintain count of index last used for Keys & also number of incorrect attempts
        ## keyIndex, incorrectAttempts = tmp.split(',')
        ## key,keyIndex,incorrectAttempts = determineKey(keyIndex, incorrectAttempts)
        # send header on connect
        self.wfile.write(b'Welcome to the Mathematical manual PIN entry system!\nPlease begin by submitting your '+str(len(key)).encode()+b' digit key one digit at a time.\nPlease enter the first digit: ')
        receivedKey = ''
        while True:
            # read in data sent from client
            self.data = self.rfile.readline().strip().decode('utf-8')
            if len(self.data) > 1:
                self.wfile.write(b"More than 1 digit receieved, please try again")
                receivedKey = ''
                continue
            receivedKey += self.data        #.decode('utf-8')
            os.system(f"echo 'Current Received Key: {receivedKey}' >> connKey.txt")
            # Check to see if full key has been sent
            if len(receivedKey) == len(key):
                #print('current Key: ',key)
                now = datetime.now()
                c_time = int(now.strftime("%H%M%S"))
                tmpkey = ((int(key) - c_time)%999999)
                keyrcv = int(receivedKey)
                newkey = int((tmpkey+keyrcv)%999999)
                keystr = str(newkey)
                #print('oldkey + current time: ',keystr)
                if str(receivedKey) == str(key):
                    self.wfile.write(b"\nThe current time is " + str(c_time).encode() + b". Correct key entered.\n\nThe submission string for door mechanism #3 is: " + flag.encode())
                    break
                self.wfile.write(b"Incorrect key of " + receivedKey.encode() + b" received at " + str(c_time).encode() + b", please try again. Expected: "+ str(key).encode())
                key = keystr.zfill(6) 
                ## incorrectAttempts += 1  
                ## key,keyIndex,incorrectAttempts = determineKey(keyIndex, incorrectAttempts)           # runs check to see if Key needs to be rotated after last failed attempt.
                receivedKey = ''
                self.wfile.write(b"\nPlease enter the first digit: ")
                continue
            try:    # Catches if client closes connection & handles Broken Pipe error
                self.wfile.write(b"Please enter next digit: ")
            except Exception as e:
                print(f"Exception caught, logging to log.txt. losing current session.")
                os.system(f"echo '{str(datetime.now())} --  Exception: {e}' >> log.txt")
                break
    
#Ensure that this IP is used on your virtual machine, or replace with the IP of your system in order for the server to run properly                
if __name__ == "__main__":
    HOST, PORT = "133.45.153.250", port

    with socketserver.TCPServer((HOST, PORT), handler_TCPServer) as server:
        # Activate the server; this will keep running until you kill the process.
        os.system(f"echo 'Serving Server: {datetime.now()}' > log.txt")
        server.serve_forever()




