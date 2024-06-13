#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, datetime
from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_apscheduler.auth import HTTPBasicAuth

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'NOT_A_TOKEN'
    SESSION_PERMANENT=False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir,'vault.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TIMER = datetime.timedelta(minutes=5)
    FLASK_APP = 'app.py'
    STATIC_FOLDER = f"{basedir}/app/static/"
    TEMPLATES_FOLDER = f"{basedir}/app/templates/"
    UPLOAD_FOLDER = f"{basedir}/app/level3/tmp/"
    # configure scheduler API
    SCHEDULER_API_ENABLED = True
    SCHEDULER_AUTH =  HTTPBasicAuth()
