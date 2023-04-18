#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys, html
from jinja2 import *
from markupsafe import Markup
from bs4 import BeautifulSoup
from flask import Blueprint, render_template, render_template_string, redirect, url_for, request, abort, Response, flash, send_from_directory, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
sys.path.insert(0, './adminSite/')
import globals, adminFuncs
from models import User

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/login/', methods=['GET', 'POST'])  
def login(): 
    if request.method=='GET': 
        return render_template('login.html')
    else: 
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True 
        user = User.query.filter_by(username=username).first()
        # check if the user actually exists
        if user == None:
            flash('Login incorrect')
            resp = make_response(render_template('login.html'),401)
            return resp
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        chkPwd = check_password_hash(user.password, password)
        if chkPwd == False:
            flash('Login incorrect')
            resp = make_response(render_template('login.html'),401)
            return resp
        # if the above check passes, then we know the user has the right credentials
        login_user(user, remember=remember)
        return redirect(url_for('admin.control'))
