#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import socket,socketserver, subprocess, json, math, time, os, hashlib, datetime, sys
import asyncore, collections, logging
import threading, time, sys, signal, select
from _thread import *


port=25490
token="34dbfd17967e"
keyvar="184303"

class handler_TCPServer(socketserver.StreamRequestHandler):       
    def handle(self):
        flag = token
        key = keyvar
        ## get current index to use & count of incorrect attempts 
        ## with open("keyInfo.txt",'r') as f:
        ##    tmp = f.read()                  # file to maintain count of index last used for Keys & also number of incorrect attempts
        ## keyIndex, incorrectAttempts = tmp.split(',')
        ## key,keyIndex,incorrectAttempts = determineKey(keyIndex, incorrectAttempts)
        # send header on connect
        self.wfile.write(b'Welcome to the Replay Lock manual PIN entry system!\nPlease begin by submitting your '+str(len(key)).encode()+b' digit key one digit at a time.')
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
                if str(receivedKey) == str(key):
                    self.wfile.write(b"Correct key entered.\n\nThe submission string for door mechanism #1 is: " + flag.encode())
                    break
                self.wfile.write(b"Incorrect key receieved, please try again.")
                ## incorrectAttempts += 1  
                ## key,keyIndex,incorrectAttempts = determineKey(keyIndex, incorrectAttempts)           # runs check to see if Key needs to be rotated after last failed attempt.
                receivedKey = ''
                continue
            try:    # Catches if client closes connection & handles Broken Pipe error
                self.wfile.write(b"Please enter next digit.")
            except Exception as e:
                print(f"Exception caught, logging to log.txt. losing current session.")
                os.system(f"echo '{datetime.datetime.now()} --  Exception: {e}' >> log.txt")
                break
    
             
if __name__ == "__main__":
    HOST, PORT = "133.45.151.250", port

    with socketserver.TCPServer((HOST, PORT), handler_TCPServer) as server:
        # Activate the server; this will keep running until you kill the process.
        os.system(f"echo 'Serving Server: {datetime.datetime.now()}' > log.txt")
        server.serve_forever()



