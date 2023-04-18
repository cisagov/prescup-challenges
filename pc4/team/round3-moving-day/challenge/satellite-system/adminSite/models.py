#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from calendar import c
from flask_login import UserMixin, AnonymousUserMixin
from flask import Flask, jsonify, make_response
from sqlalchemy.orm import declarative_base, relationship
from __init__ import db

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
    created = db.Column(db.String, nullable=False)
