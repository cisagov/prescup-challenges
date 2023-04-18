#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import socket,socketserver, subprocess, json, math, time, os, hashlib, datetime, random
import asyncore, collections, logging
import threading, time, sys, signal, select
from _thread import *


port=28216
token="37cac465a937" 
klist="364764 556893 602702 912521 749644 215285 895790 981308 326878 532705"

class handler_TCPServer(socketserver.StreamRequestHandler):       
    def handle(self):
        incorrectAttempts = 0
        flag = token
        keylist = list(map(int,klist.split()))
        seed = random.randint(0, 9) #int(subprocess.run("vmware-rpctool 'info-get guestinfo.s1'",shell=True, capture_output=True).stdout.decode('utf-8').strip('\n'))
        startingkey = str(keylist[seed]).strip('\n')
        ## get current index to use & count of incorrect attempts 
        ## with open("keyInfo.txt",'r') as f:
        ##    tmp = f.read()                  # file to maintain count of index last used for Keys & also number of incorrect attempts
        ##keyIndex, incorrectAttempts = tmp.split(',')
        ##key,keyIndex,incorrectAttempts = determineKey(keyIndex, incorrectAttempts)
        # send header on connect
        self.wfile.write(b'Welcome to the Sequencer manual PIN entry system!\nPlease begin by submitting your '+str(len(startingkey)).encode()+b' digit key one digit at a time.\nPlease enter the first digit: ')
        receivedKey = ''
        #a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        #i = 0
        #for i in a:
        while True:
        # read in data sent from client
            self.data = self.rfile.readline().strip().decode('utf-8')
            if len(self.data) > 1:
                self.wfile.write(b"More than 1 digit received, please try again\n")
                receivedKey = ''
                continue
            receivedKey += self.data        #.decode('utf-8')
            os.system(f"echo 'Current Received Key: {receivedKey}' >> connKey.txt")
            # Check to see if full key has been sent
            if len(receivedKey) == len(startingkey):
                if str(receivedKey) == str(startingkey):
                    self.wfile.write(b"\nCorrect key entered.\n\nThe submission string for door mechanism #2 is: " + flag.encode() + b"\n")
                    #i += 1                    
                    seed = ((seed + 1)%10)
                    startingkey = str(keylist[seed]).strip('\n')     
                    break                 
                self.wfile.write(b"Incorrect key received, please try again. Expected: " + startingkey.encode()+b'\n')
                #i += 1
                seed = ((seed + 1)%10)
                startingkey = str(keylist[seed]).strip('\n')
                incorrectAttempts += 1
                if incorrectAttempts > 2:
                    self.wfile.write(b"60 lockout initiated\n")
                    incorrectAttempts = 0
                    time.sleep(30)
                    self.wfile.write(b"30 seconds remaining on lockout\n")
                    time.sleep(30)
                    self.wfile.write(b"Goodbye\n")
                    break
                ## key,keyIndex,incorrectAttempts = determineKey(keyIndex, incorrectAttempts)           # runs check to see if Key needs to be rotated after last failed attempt
                receivedKey = ''
                self.wfile.write(b"Please enter the first digit: ")
                continue
            try:    # Catches if client closes connection & handles Broken Pipe error
                self.wfile.write(b"Please enter next digit: ")
            except Exception as e:
                print(f"Exception caught, logging to log.txt. losing current session.")
                os.system(f"echo '{datetime.datetime.now()} --  Exception: {e}' >> log.txt")
                break
    
             
if __name__ == "__main__":
    HOST, PORT = "133.45.152.250", port

    with socketserver.TCPServer((HOST, PORT), handler_TCPServer) as server:
        # Activate the server; this will keep running until you kill the process.
        os.system(f"echo 'Serving Server: {datetime.datetime.now()}' > log.txt")
        server.serve_forever()


