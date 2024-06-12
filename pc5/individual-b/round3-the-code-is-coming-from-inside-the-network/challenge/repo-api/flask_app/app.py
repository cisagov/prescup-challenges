#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from app import create_app
from flask_apscheduler import APScheduler
import app.globals as globals
from app.functions import rotate_auth_token

scheduler = APScheduler()
app = create_app()
if __name__ == '__main__':
    scheduler.add_job(id="rotate_auth_token",func=rotate_auth_token,trigger="interval",seconds=globals.auth_rotate_time)
    scheduler.start()
    app.run("0.0.0.0", port=5000, debug=False)
