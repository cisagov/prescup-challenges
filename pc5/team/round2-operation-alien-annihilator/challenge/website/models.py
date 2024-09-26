#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from calendar import c
from flask_login import UserMixin, AnonymousUserMixin
from flask import Flask, jsonify, make_response
from sqlalchemy.orm import declarative_base, relationship
from __init__ import db
import funcs, json

class Anonymous(AnonymousUserMixin):
    id = 0
    username = 'Guest'
    email = ''
    role = None    

class User(UserMixin):
    def __init__(self, email, username,  roles):
        self.id = email
        self.username = username
        self.role = roles

    @staticmethod
    def get(id):
        resp = funcs.search(id)
        resp_dict = json.loads(resp.text)
        role_list = resp_dict[0]['roles'].split(' ')
        role = "system_admin" if "system_admin" in role_list else "system_user"
        user=User(resp_dict[0]['email'], resp_dict[0]['username'], role.split(' ')[0])
        return user

class File(db.Model):
    __tablename__ = 'File'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    user_username = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    role = db.Column(db.String, nullable=False)
    blob = db.Column(db.VARCHAR(10000000), nullable=False)
    uploaded = db.Column(db.String, nullable=False)

    __fs_fields__ = ['name', 'user_id', 'user_username','blob', 'role']

    def __repr__(self):
        return '<File %r %r %r %r %r>' % (self.name, self.user_id, self.user_username, self.blob, self.role)
