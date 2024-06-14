
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, random
from flask_apscheduler import APScheduler
from requests.auth import HTTPBasicAuth


global scheduler
scheduler = APScheduler()

global basedir
basedir = os.path.abspath(os.path.dirname(__file__))

global attempts
attempts = 0

global request_auth
request_auth = HTTPBasicAuth("gold","roger")

global t1
t1 = "#t1"

global t2
t2 = "#t2"
