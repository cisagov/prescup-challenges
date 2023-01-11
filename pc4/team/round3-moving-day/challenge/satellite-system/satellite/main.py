#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys, html, threading, json
from jinja2 import *
from markupsafe import Markup
from bs4 import BeautifulSoup
from flask import Blueprint, render_template, render_template_string, redirect, url_for, request, abort, Response, flash, send_from_directory, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
sys.path.insert(0, './')
import globals, satFuncs
from models import User

main = Blueprint('main', __name__)

@main.before_app_first_request
def getStatus():
    satFuncs.getCurrentState()
    globals.status['cmd_running'] = "False"

@main.after_request
def after_request(response):
    satFuncs.checkCoordinates()
    with open('./static/shutdownInfo', 'w') as f:
        f.write(json.dumps(globals.shutdownInfo))
    with open('./static/fileInfo','w') as f:
        f.write(json.dumps(globals.fileInfo))
    with open('./static/status', 'w') as f:
        f.write(json.dumps(globals.status))
    response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN') #request.headers['Origin']
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    return response
    
@main.route('/')
def index():
    if globals.shutdownInfo['offline'] == "True":
        return render_template_string('Satellite Offline')
    return render_template_string('Satellite Station.')

@main.route('/status')
def getstatus():
    if globals.shutdownInfo['offline'] == "True":
        return render_template_string('Satellite Offline')
    currentstatus = json.dumps(globals.status)
    return render_template_string(currentstatus)

@main.route('/run')
def runCmds():
    if globals.shutdownInfo['offline'] == "True":
        return render_template_string('Satellite Offline')
    temp = """
    <script>
        console.log('Use following command format when passing "cmd" arg:')
        console.log('[azimuth OR elevation]:[+1 OR -1]:[degree OR minute OR second]')
        console.log('multiple move commands must be separated by a period(.)')
        console.log('Command must be URL encoded')
    </script><br>
    """
    cmd = request.args.get('cmd')
    if (cmd == '') or (cmd == None):
        return render_template_string(f"{temp}No commands received.")
    sendCmd = threading.Thread(target=satFuncs.moveSat,args=(cmd,))
    sendCmd.start()
    
    return render_template_string("Movement Initiated.")


@main.route('/shutdown')
def sequence():
    ## Verifys satellite shutdown sequence sent from admin site
    if request.referrer == None:                     #'123.45.67.100:5000' not in request.referrer:
        return 'Unauthorized. Request must come from /admin/emergency-SD/'
    if globals.shutdownInfo['offline'] == "True":
        return render_template_string('Satellite Offline.')
    if globals.fatal == 'False':
        return render_template_string('Satellite shutdown not available.')
    timeStatus = satFuncs.checkTimeout()
    if timeStatus != 'pass':
        return f"Timeout ends at {globals.shutdownInfo['timein']}"
    seq = request.args.get('seq')
    
    if (seq == '') or (seq == None):
        return render_template_string("No commands received.")
    chkSeq = satFuncs.shutdownSequence(seq.strip('\n'))
    return render_template_string(chkSeq)
    
