#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, AnonymousUserMixin, user_logged_out
from __init__ import create_app, db
from models import Sensor
from flask_apscheduler import APScheduler
from flask import current_app
import globals

def cleanup():
    with app.app_context():
        for k,v in globals.thread_tracker.items():
            if v == None:
                continue
            elif v.is_alive() == False:
                globals.thread_tracker[k] = None
        
def check_sensors():
    with app.app_context():
        all_Sensors = Sensor.query.all()
        for sensor in all_Sensors:
            if sensor.curr_temp > sensor.overheat:
                sensor.online = False
                db.session.commit()

scheduler=APScheduler()
if __name__ == "__main__":
    app = create_app()
    scheduler.add_job(id="cleanup",func=cleanup,trigger="interval",seconds=5)
    scheduler.add_job(id="status",func=check_sensors,trigger="interval",seconds=2)
    scheduler.start()
    app.run(host='0.0.0.0',port=8374,debug=False)
