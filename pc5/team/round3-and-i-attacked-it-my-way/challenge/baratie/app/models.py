#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask_login import UserMixin, AnonymousUserMixin
from app.extensions import db

class Anonymous(AnonymousUserMixin):
    id = 0
    name = 'Guest'
    username = 'Guest'
    email = ''
    password = ''
    role = None    

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
