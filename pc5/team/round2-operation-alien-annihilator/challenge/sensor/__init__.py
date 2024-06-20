#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
def create_app():
    app = Flask(__name__) 
    app.config['SECRET_KEY'] = 'NOT_A_TOKEN' 
    app.config['ACCEPTED_IP'] = ['10.7.7.7','10.5.5.5','10.3.3.52','127.0.0.1']
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'site.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
    
    from main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    db.init_app(app) # Initialiaze sqlite database
    with app.app_context():
        db.create_all()
    return app

