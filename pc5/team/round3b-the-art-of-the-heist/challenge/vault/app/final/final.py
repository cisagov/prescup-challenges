
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, redirect, url_for, make_response
from flask_login import current_user
from app.functions import *
import app.globals as globals
from functools import wraps


final = Blueprint("final",__name__,static_folder=f"{globals.basedir}/final/static/",template_folder=f"{globals.basedir}/final/templates/")   

def login_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("level1.login"))
        level_check = check_local_user(current_user.username)
        if level_check.passed['level3'] != True:   
            return redirect(url_for("level3.submit_id"))
        if callable(getattr(current_app, "ensure_sync",None)):
            return current_app.ensure_sync(view_func)(*args,**kwargs)
        return view_func(*args,**kwargs)
    return decorated_view


@final.context_processor
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
    

@final.route("/",methods=['GET','POST'])
@login_required
def success():
    return render_template("success.html", t2=globals.t2)
