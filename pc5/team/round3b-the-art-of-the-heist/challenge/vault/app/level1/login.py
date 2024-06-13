
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, make_response, flash, url_for, redirect
from flask_login import login_user, current_user
from app.functions import *
import app.globals as globals
from app.models import RcUser
from functools import wraps

level1 = Blueprint("level1",__name__,static_folder=f"{globals.basedir}/level1/static/",template_folder=f"{globals.basedir}/level1/templates/")    

@level1.route("/", methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("level2.submit_pin"))
    if request.method=='GET': 
        return render_template('login.html')
    else: 
        email = request.form.get('email')
        password = request.form.get('password')
        user_resp = check_user(email, password)
        if user_resp == "error":
            return redirect(url_for("level1.login"))
        if (user_resp == None) or (user_resp == False):
            flash('Email and/or password incorrect, please try again.')
            resp = make_response(render_template('login.html'),401)
            return resp
        user = RcUser(user_resp)
        if 'system_admin' not in user.roles:
            flash("Admin account required for access")
            resp = make_response(render_template('login.html'),401)
            return resp
        login_user(user)
        create_and_start()
        passed_level("level1")
        globals.attempts = 0
        return redirect(url_for('level2.submit_pin'))

