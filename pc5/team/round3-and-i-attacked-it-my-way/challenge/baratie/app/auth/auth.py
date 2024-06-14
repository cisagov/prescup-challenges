
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, redirect, url_for
from flask_login import login_user, logout_user, current_user, login_required
from app.extensions import db
from app.functions import *
from app.models import Anonymous, User
import app.globals as globals

auth = Blueprint("auth",__name__)

@auth.route("/success", methods=["GET","POST"])
@auth.route("/success/", methods=["GET","POST"])
@login_required
def success():
    id = request.args.get('id')
    try:
        globals.login_status['successful'].remove(id)
    except:
        ...
    return render_template("success.html")

@auth.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
