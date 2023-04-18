#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, subprocess, random, sys
from flask import Flask, session, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.debug import DebuggedApplication
sys.path.insert(0, './adminSite/')

db = SQLAlchemy()
def create_app():
    app = Flask(__name__) 
    app.config['SECRET_KEY'] = 'THIS_IS_NOT_PART_OF_THE_CHALENGE' 
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'db.site')  # needs to be able to connect to sql db
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

    db.init_app(app) 
    from models import User, Anonymous 
    login_manager = LoginManager() 
    login_manager.login_view = 'main.login' 
    login_manager.session_protection = None
    login_manager.anonymous_user = Anonymous
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    from admin import admin as admin_blueprint
    app.register_blueprint(admin_blueprint, url_prefix='/admin')

    @app.errorhandler(404)
    def page_not_found(e):
        return redirect(url_for("main.index")),404,{"Refresh":"1;url=/"}

    return app
