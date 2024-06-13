
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, os, datetime, time, re
from flask import Blueprint, render_template_string, render_template, request, current_app, make_response, flash, url_for, redirect, session, send_from_directory, send_file
from flask_login import login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from app.functions import *
from app.models import Anonymous, User
import app.globals as globals


main = Blueprint("main",__name__)

@main.route("/login", methods=["GET","POST"])
@main.route('/login/', methods=['GET', 'POST']) 
def login():
    if globals.timeout['active'] == True:
        return render_template('login.html',timeout=True)
    if request.method=='GET': 
        return render_template('login.html')
    else:
        un = request.form.get("username")
        pwd = request.form.get("password")

        expressions = {      
            "un": f"select * from user where username='{un}';",
            "full":f"select * from user where username='{un}' and password='{pwd}';"
        }
        query_resp = runExpression(expressions)
        if query_resp == False:      
            # If username not found
            globals.timeout['active'] = True
            globals.timeout['end_time'] = datetime.datetime.now() + globals.timeout['timeout_length']
            return render_template('login.html',timeout=True)
        elif query_resp == None:
            flash("Incorrect Credentials Entered")
            return render_template('login.html')
        elif query_resp == True:
            try:
                user = User.query.filter_by(username=un, password=pwd).first()
            except Exception as e:
                flash("Authentication Failed")
                return render_template('login.html')
            if user == None:
                flash("Authentication Failed")
                return render_template('login.html')
            login_user(user)
            return redirect(url_for('auth.success'))
        

