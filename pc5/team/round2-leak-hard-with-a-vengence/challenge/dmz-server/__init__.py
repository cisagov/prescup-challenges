#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

db = SQLAlchemy()
def create_app():
    app = Flask(__name__) 
    app.config['SECRET_KEY'] = 'NOT_A_TOKEN' 
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'site.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    app.config['SESSION_COOKIE_HTTP'] = False
    db.init_app(app) # Initialiaze sqlite database

    from models import Anonymous 
    login_manager = LoginManager() # Create a Login Manager instance
    login_manager.login_view = 'blog.index' # define the redirection path when login required and we attempt to access without bnager.init_app(app) # configin
    login_manager.session_protection = None
    login_manager.anonymous_user = Anonymous
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id): #reload user object from the user ID stored in the session
        return login_manager.anonymous_user

    from blog import blog as blog_blueprint
    app.register_blueprint(blog_blueprint)  #, url_prefix='/blog'

    with app.app_context():
        db.create_all()
    return app
