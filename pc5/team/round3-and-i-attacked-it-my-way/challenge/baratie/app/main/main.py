
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, os
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, make_response, flash, url_for, redirect, session, send_from_directory, send_file
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from app.functions import *
from app.models import Anonymous, User
import app.globals as globals


main = Blueprint("main",__name__)

@main.route("/login", methods=["GET","POST"])
@main.route("/login/", methods=["GET","POST"])
def login():
    if request.method=='GET':
        return render_template('login.html')
    else: 
        username = request.form.get('username')
        password = request.form.get('password')     
        id = next(globals.queue_id_counter)
        globals.login_queue.put((str(id),username,password))
        globals.login_status["pending"].append(str(id))
        if globals.currently_queued_id == None:
            globals.currently_queued_id = id
        session['un'] = username
        session['pwd'] = password
        session['id'] = id
        return redirect(url_for('main.login_queue'))


@main.route("/login/queue",methods=["GET","POST"])
@main.route("/login/queue/",methods=["GET","POST"])
def login_queue():
    my_id = session.get("id")
    if request.referrer in ["http://baratie.merch.codes/login","http://baratie.merch.codes/login/"]:   
        return render_template("queue.html", my_id=my_id)
    elif request.referrer in ["http://baratie.merch.codes/login/queue","http://baratie.merch.codes/login/queue/"]:
        try:
            id = int(request.args.get('id'))
        except Exception as e:
            flash("Unable to retrieve session info. Please try again.")
            return redirect(url_for('main.login'))
        if id != my_id:
            flash("Session mismatch found. Please try logging in again.")
            return redirect(url_for('main.login'))
        if str(id) in globals.login_status['successful']:
            un = session.get('un')
            user = User.query.filter_by(username=un).first()
            login_user(user)
            return redirect(url_for('auth.success',id=id))
        elif (str(id) in globals.login_status['failed']):
            flash("Incorrect Credentials Entered. Please Try Again")
            globals.login_status['failed'].remove(str(id))
            return redirect(url_for('main.login'))
        elif (str(id) in globals.login_status['none']):
            flash("Incorrect Credentials Entered. Please Try Again")
            globals.login_status['none'].remove(str(id))
            return redirect(url_for('main.login'))
        else:
            print(f"Unknown request made.\nmy_id: {my_id}\nPassed 'id': {id}")
            return redirect(url_for('main.login'))
    else:
        #return jsonify({"Status":f"Request Received. Session cookies for tracking: {request.cookies}"})
        flash(f"Request Received. Session cookies for tracking: {request.cookies}")
        return redirect(url_for('main.login'))

@main.route("/overloaded",methods=['GET','POST'])
@main.route("/overloaded/",methods=['GET','POST'])  
def failsafe():
    if globals.failsafe != True:
        return redirect(url_for("main.login"))
    return render_template("failsafe.html")

@main.route("/download/",methods=['GET','POST'], defaults={"fn":""})
@main.route("/download/<path:fn>",methods=['GET','POST'])
def download(fn):
    if globals.failsafe != True:
        return redirect(url_for("main.login"))
    if fn == "":
        return jsonify({"Files":{"1":"dad_jokes","2":"dad_jokes2","3":"cross_guild","4":"backup","5":"recipes"}})
    full_filename = f"{globals.basedir}/files/{fn}"
    if os.path.isfile(full_filename):
        return send_file(full_filename,as_attachment=True,download_name=fn)

