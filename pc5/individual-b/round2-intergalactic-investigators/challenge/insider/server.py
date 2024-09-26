#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, socketserver, subprocess, json, datetime
import pandas as pd
from pathlib import Path
from _thread import *

class handler_TCPServer(socketserver.StreamRequestHandler):       
    def handle(self):
        dataset = pd.read_csv("./dataset.csv", keep_default_na=False,na_filter=False).to_dict('index')
        dataset_vals = list(dataset.values())
        with open("./stars_planets.json",'r') as f:
        	sp = json.loads(f.read())
	
        self.wfile.write(b"Initiating transfer of information on Stars and Planets...\n")
        self.wfile.write(b'Stars: ' + str(sp['stars']).encode()+b'\n')
        self.wfile.write(b'Planets: ' + str(sp['planets']).encode()+b'\n\n')
        
        self.wfile.write(b"Initiating transfer dataset...\n")
        self.wfile.write(str(dataset_vals).encode()+b'\n\n')
        self.wfile.write(b"Data transfer completed.\n")
            
if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 33333

    with socketserver.TCPServer((HOST, PORT), handler_TCPServer) as server:
        # Activate the server; this will keep running until you kill the process.
        os.system(f"echo 'Serving Server: {datetime.datetime.now()}' > ./log")    # write server start time to /home/user/Desktop/log file.
        server.serve_forever()
        
#for k,v in coordinates.items():
#    self.wfile.write(str(v).encode())
