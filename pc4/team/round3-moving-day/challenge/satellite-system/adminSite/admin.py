#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from io import StringIO
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, g, make_response, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db
from sqlalchemy.sql import text
from pathlib import Path
import sys, datetime, io, json, subprocess, threading, os
sys.path.insert(0, './adminSite/')
import adminFuncs, globals


admin = Blueprint('admin', __name__) 

@admin.route('/control/', methods=['GET','POST'])
@login_required
def control():
    if request.method == 'GET':
        return render_template('control.html')
    else:
        cmdStr = request.form.get('commands')
        output = adminFuncs.syntaxCheck(cmdStr, 'cmd')
        if type(output) == list:
            for x in output:
                flash(x)
            return redirect(url_for('admin.control'))
        threading.Thread(target=adminFuncs.sendCommands,args=(output,)).start()
        return render_template('control.html')          

@admin.route('/netstorage/', methods=['GET','POST'])      
@login_required
def storage():
    fn = request.args.get('filename')
    fileList = os.listdir(globals.storageLoc)
    if fn != None:
        if fn in fileList:
            return send_from_directory(globals.storageLoc,fn, as_attachment=True)
        elif fn == '*':
            return render_template('storage.html',fileList=fileList)
        else:
            flash("File does not exist")
            return render_template('storage.html')
    else:
        return render_template('storage.html')

@admin.route('/emergency-SD/', methods=['GET','POST'])        
@login_required
def shutdown():
    if request.method == 'GET':
        return render_template('shutdown.html')
    else:
        btnSeq = request.args.get('seq')
        output = adminFuncs.syntaxCheck(btnSeq, 'seq')
        if type(output) == list:
            for x in output:
                flash(x)
            return redirect(url_for('admin.shutdown'))
        threading.Thread(target=adminFuncs.sendSequence,args=(output,)).start()
        return render_template('shutdown.html')  

@admin.route('/logout/')
@login_required
def logout(): 
    logout_user()
    return redirect(url_for('main.index'))

