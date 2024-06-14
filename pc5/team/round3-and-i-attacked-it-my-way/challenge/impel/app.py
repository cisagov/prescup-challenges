#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys
from app import create_app
from app.globals import scheduler
from app.functions import check_timeout_endtime

app = create_app()
if __name__ == '__main__':
    scheduler.init_app(app)
    scheduler.add_job(id="check_timeout",func=check_timeout_endtime,trigger="interval",seconds=.5)       # , max_instances=2
    scheduler.start()
    app.run("0.0.0.0", port=80, debug=False)
