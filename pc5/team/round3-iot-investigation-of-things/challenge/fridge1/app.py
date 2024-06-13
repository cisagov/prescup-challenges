#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os
from app import create_app
from app.extensions import *
from app.functions import *


app= create_app()
if __name__ == '__main__':
    scheduler.init_app(app)
    scheduler.add_job(id="check temp",func=alter_temp,trigger="interval",seconds=60)
    scheduler.add_job(id="send data",func=send_data,trigger="cron",minute="*",second="39")
    scheduler.add_job(id="update",func=check_update,trigger="interval",seconds=20)             #,trigger="cron",minute="*",second="59")
    scheduler.start()
    app.run("0.0.0.0", port=80, debug=False)
