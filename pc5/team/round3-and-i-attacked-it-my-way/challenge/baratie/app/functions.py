
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


#from app.globals import login_queue, login_status, queue_status, currently_queued_id
import app.globals as globals
from flask import jsonify, session, flash, make_response, render_template
from werkzeug.security import generate_password_hash,check_password_hash
from app.models import User
from app.globals import scheduler
import time, json

def verify_creds(username, password):
    time.sleep(.5)
    try:
        user = User.query.filter_by(username=username).first()
    except Exception as e:
        return False
    if user == None:
        return None
    if not check_password_hash(user.password,password):
        return False
    return True

def process_queue():
    with scheduler.app.app_context():
        if globals.login_queue.empty():
            return
        globals.currently_queued_id, un, pwd = globals.login_queue.get()
        globals.login_status['pending'].remove(str(globals.currently_queued_id))
        login_resp = verify_creds(un,pwd)
        if login_resp:
            globals.login_status['successful'].append(str(globals.currently_queued_id))
        elif login_resp == False:
            globals.login_status['failed'].append(str(globals.currently_queued_id))
        elif login_resp == None:
            globals.login_status['none'].append(str(globals.currently_queued_id))
        globals.login_queue.task_done()
        return

def queue_status():
    status = dict()
    status['queue_size'] = globals.login_queue.qsize()
    half_sec_queue = globals.login_queue.qsize() // 4
    minutes = half_sec_queue // 60
    seconds = half_sec_queue % 60
    if len(str(seconds)) == 1:
        seconds = f"0{seconds}"
    status['est_time'] = f"~{minutes}:{seconds}"
    return jsonify(status)

def get_queue_info():
    globals.queue_status['size'] = globals.login_queue.qsize()
    globals.queue_status['current_id'] = globals.currently_queued_id
    globals.queue_status['id_status'] = "pending"                       
    for k,v in globals.login_status.items():
        if str(globals.currently_queued_id) in v:
            globals.queue_status['id_status'] = k
            break
    return json.dumps(globals.queue_status)

def check_queue_size():
    with scheduler.app.app_context():
        if globals.failsafe == True:
            if globals.login_queue.empty():
                globals.failsafe = False
        elif globals.login_queue.full():
            globals.failsafe = True


