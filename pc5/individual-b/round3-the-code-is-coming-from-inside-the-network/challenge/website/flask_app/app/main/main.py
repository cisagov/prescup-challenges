
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Blueprint, render_template, request, make_response, flash, url_for, redirect
from flask_login import login_user
from werkzeug.security import check_password_hash
from app.functions import *
from app.models import User

main = Blueprint("main",__name__,static_folder="/home/user/Desktop/flask_app/app/static/",template_folder="/home/user/Desktop/flask_app/app/templates/")     # add path to templates/static if error

@main.route("/", methods=["GET","POST"])
def index():
    return render_template("index.html")

@main.route("/login", methods=["GET","POST"])
@main.route("/login/", methods=["GET","POST"])
def login():
    if request.method=='GET': 
        return render_template('login.html')
    else: 
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True 
        user = User.query.filter_by(username=username).first()
        if user == None:
            flash('Login incorrect')
            resp = make_response(render_template('login.html'),401)
            return resp
        if not check_password_hash(user.password, password):
            flash('Login incorrect')
            resp = make_response(render_template('login.html'),401)
            return resp
        login_user(user, remember=remember)
        return redirect(url_for('auth.get_profile'))

