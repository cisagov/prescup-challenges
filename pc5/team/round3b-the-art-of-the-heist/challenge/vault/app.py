#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os, datetime, atexit, signal
from flask_login import current_user
from flask import request, jsonify
from app import create_app
from app.globals import scheduler
from app.models import LocalUser
from app.extensions import loc_db
from app.functions import restart_timer, scheduler_auth, my_listener
from apscheduler.events import EVENT_ALL, EVENT_JOB_MODIFIED ,EVENT_ALL_JOBS_REMOVED, EVENT_JOB_ERROR, EVENT_JOB_REMOVED, EVENT_SCHEDULER_PAUSED, EVENT_SCHEDULER_SHUTDOWN


def signal_handler(sig, frame):
    try:
        with app.app_context():
            scheduler.remove_all_jobs()
            session_list = LocalUser.query.all()
            for sesh in session_list:
                try:
                    loc_db.session.delete(sesh)
                    loc_db.session.commit()
                except:
                    continue
            print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Shutting Down Server.'")
        sys.exit(0)
    except Exception as e:
        print(f"Error shutting down:\n {e}")


if __name__ == '__main__':
    app = create_app()
    scheduler.init_app(app)
    scheduler.add_listener(my_listener,EVENT_JOB_MODIFIED|EVENT_ALL_JOBS_REMOVED|EVENT_JOB_ERROR|EVENT_JOB_REMOVED|EVENT_SCHEDULER_PAUSED|EVENT_SCHEDULER_SHUTDOWN)
    scheduler.add_job(id="restart_timer",func=restart_timer,trigger="interval",seconds=15)
    scheduler.start()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    @scheduler.authenticate
    def authenticate(auth):
        with app.app_context():
            if (request.remote_addr == '10.7.7.7') or (request.remote_addr == "10.3.3.17"):
                return True
            if scheduler_auth(auth['username'],auth['password']):
                return True
            else:
                print(auth['username'], auth['password'])
                return False

    app.run("0.0.0.0", port=80, debug=False)

