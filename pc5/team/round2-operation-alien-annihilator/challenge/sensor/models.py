#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from calendar import c
from flask_login import UserMixin, AnonymousUserMixin
from flask import Flask, jsonify, make_response
from sqlalchemy.orm import declarative_base, relationship
from __init__ import db
from flask_serialize import FlaskSerialize

fs_mixin = FlaskSerialize(db)

class Sensor(db.Model, fs_mixin):
    __tablename__ = 'Sensor'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    curr_temp = db.Column(db.Integer, nullable=False)
    set_temp = db.Column(db.Integer, nullable=False)
    overheat = db.Column(db.Integer, nullable=False)
    last_update = db.Column(db.String, nullable=False)
    online = db.Column(db.Boolean, nullable=False)

    __fs_fields__ = ['name','curr_temp','set_temp','overheat','last_update','online'] 

    def __repr__(self):
        return '<Sensor %r %r %r %r %r %r>' % (self.id, self.name, self.curr_temp, self.set_temp, self.last_update, self.online)

    def __fs_can_delete__(self):
        return False
