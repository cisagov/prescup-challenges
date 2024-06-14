
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, redirect, url_for, make_response
from flask_login import login_user, current_user
from app.functions import *
import app.globals as globals
from functools import wraps


level2 = Blueprint("level2",__name__,static_folder=f"{globals.basedir}/level2/static/",template_folder=f"{globals.basedir}/level2/templates/")   

def login_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("level1.login"))
        level_check = check_local_user(current_user.username)
        if level_check.passed['level2'] == True:
            return redirect(url_for("level3.submit_id"))
        elif globals.attempts > 4:
            flash("More than 5 incorrect attempts made, logging out.")
            logout()
            return redirect(url_for("level1.login"))
        if callable(getattr(current_app, "ensure_sync",None)):
            return current_app.ensure_sync(view_func)(*args,**kwargs)
        return view_func(*args,**kwargs)
    return decorated_view

@level2.context_processor
@login_required
def inject_data():
    data = check_local_user(current_user.username)
    if data != False:
        return {
            "t1":globals.t1,
            "time_left":data.time_left
        }
    else:
        return {
            "t1":globals.t1
        }


@level2.route("/", methods=["GET","POST"])
@login_required
def submit_pin():
    if request.method=='GET': 
        return render_template('pin.html')
    else: 
        submitted_pin = request.form.get('pin')
        data = {
            "function":"verify",
            "username": current_user.username,
            "pin":submitted_pin
        }
        try:
            check_pin_response = requests.post("http://shiamazu.merch.codes/",headers={"Content-Type":"application/json"} ,json=data, auth=request_auth)
        except Exception as e:
            flash("Unable to authenticate submitted pin. Please check network settings and try again.")
            return redirect(url_for('level2.submit_pin'))
        try:
            bad_resp = check_pin_response.json()
            flash(json.dumps(bad_resp,indent=2))
            globals.attempts += 1
            return redirect(url_for('level2.submit_pin'))
        except Exception as e:
            ...

        pin_resp = check_pin_response.text
        if (pin_resp == '') or (pin_resp == None):
            flash('None or empty response received. Please try again')
            return redirect(url_for('level2.submit_pin'))
        if pin_resp == 'Failure':
            flash('Incorrect Pin entered for your account. Please try again.')
            globals.attempts += 1
            return redirect(url_for('level2.submit_pin'))
        
        passed_level("level2")
        return redirect(url_for('level3.submit_id'))

