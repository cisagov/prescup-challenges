
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, random
from flask_apscheduler import APScheduler
from requests.auth import HTTPBasicAuth

global basedir
basedir = os.path.abspath(os.path.dirname(__file__))   
