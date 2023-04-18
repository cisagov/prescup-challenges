#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import logging, subprocess, sys
from flask import g

from admin import storage


# create global logger for site
logFormat = f"ADMIN-SITE | %(levelname)s | %(message)s"
logging.basicConfig(format=logFormat,level=logging.INFO)
logger = logging.getLogger("adminSite")

# storage location
global storageLoc
storageLoc = './static/storage/' # '#storage'

# satellite port
global satPort
satPort = '5050'

# objects that will deal with sending/receiving commands (cmds sent, time remained, etc.)
global max_cmds
global cmd_running
max_cmds = 5
cmd_running = 'False'

# object that contains accepted syntax/format of satellite moving commands
global cmdSyntax
cmdSyntax = ['move',['azimuth','elevation'],['-1','+1'],['degree','minute','second']]

# object holding current status of satellite
global satStatus
satStatus = 'working'
