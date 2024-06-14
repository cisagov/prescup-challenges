#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys
from app import create_app
from app.globals import scheduler
from app.functions import process_queue, check_queue_size


app = create_app()
if __name__ == '__main__':
    scheduler.init_app(app)
    scheduler.add_job(id="proc_queue",func=process_queue,trigger="interval",seconds=.25, max_instances=20)
    scheduler.add_job(id="queue_failsafe",func=check_queue_size,trigger="interval",seconds=1)
    scheduler.start()
    app.run("0.0.0.0", port=80, debug=False)
