
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, queue
from itertools import count
from flask_apscheduler import APScheduler

global scheduler
scheduler = APScheduler()

global basedir
basedir = os.path.abspath(os.path.dirname(__file__))

global login_queue
login_queue = queue.Queue(maxsize=500)

global failsafe
failsafe = False

global login_status
login_status = {
    "successful":[],
    "failed":[],
    "none":[],
    "pending":[]
}

global currently_queued_id
currently_queued_id = None

global queue_id_counter
queue_id_counter = count(start=1)

global queue_status
queue_status = dict()

