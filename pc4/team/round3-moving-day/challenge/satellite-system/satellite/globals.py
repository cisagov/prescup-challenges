#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from asyncio import current_task
import logging, subprocess, sys, json

# create global logger for site
logFormat = f"SATELLITE | %(levelname)s | %(message)s"
logging.basicConfig(format=logFormat,level=logging.INFO)
logger = logging.getLogger("satellite")

# load current config 
global status
with open('./static/status') as f:
    status = json.loads(f.read())

# load info on files
global fileInfo
with open('./static/fileInfo','r') as f:
    fileInfo = json.loads(f.read())

# load file that contains correct coordinates
global fileCoor
with open('./static/fileCoordinates','r') as f:
    fileCoor = json.loads(f.read())

# load shutdown info
global shutdownInfo
with open('./static/shutdownInfo','r') as f:
    shutdownInfo = json.loads(f.read())

# set timeout length 
global timeoutLength
timeoutLength = 60

# If all 3 files have been gotten, use this variable to track when it goes into final 'fatal' mode 
global fatal
fatal = 'False'

# storage location
global storage
storage = './static/storage/' #'#storage'

# objects dealing with cmds being ran
global timePerCmd
global max_cmds
timePerCmd = 5
max_cmds = 5

# object to handle cmds during 3rd state
global state3CmdTracker
state3CmdTracker = 0

# objects to hold coordinates of each file, file info, and the current state
global files
files = [fileCoor['f1'], fileCoor['f2'], fileCoor['f3']]
