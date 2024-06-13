
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, datetime
from flask_apscheduler import APScheduler

global basedir
basedir = os.path.abspath(os.path.dirname(__file__))

global scheduler
scheduler = APScheduler()

global timeout
timeout = {
    "active": False,
    "timeout_length": datetime.timedelta(seconds=.25),
    "end_time": datetime.datetime.now()
}


