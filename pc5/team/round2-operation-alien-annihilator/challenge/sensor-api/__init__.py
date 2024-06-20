#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

def create_app():
    app = Flask(__name__) 
    app.config['SECRET_KEY'] = 'NOT_A_TOKEN' 
    
    from main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app

