
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import time, datetime
import app.globals as globals
from flask import jsonify, session, flash, make_response, render_template, request, redirect, url_for
from sqlalchemy import text
from werkzeug.security import generate_password_hash,check_password_hash
from app.models import User
from app.globals import scheduler
from app.extensions import db

def check_timeout_endtime():
    with scheduler.app.app_context():
        if datetime.datetime.now() > globals.timeout['end_time']:
            globals.timeout['active'] = False

def get_timeout_status():
    with scheduler.app.app_context():
        if request.referrer == "http://impel.merch.codes/login/":
            return jsonify({"status":globals.timeout['active']})
        flash("Unauthorized")
        return redirect(url_for("main.login"))



def runExpression(expressions):
    username_expression = text(expressions['un'])
    full_expression = text(expressions['full'])
    try:
        un_resp = db.session.execute(username_expression).scalar() is not None
        if not un_resp:
            return un_resp
    except Exception as e:
        print(f"ERROR: -- Most likely error from bad SQL Inject, error from Username textbox. Error Msg Below.\n{e}")
        return False
    
    try:
        full_resp = db.session.execute(full_expression).first()
        if full_resp == None:
            return full_resp
        return True
    except:
        print(f"ERROR: -- Most likely error from bad SQL Inject, error from Username textbox. Error Msg Below.\n{e}")
        return None
    

