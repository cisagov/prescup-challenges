#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import yaml
from flask_login import UserMixin, AnonymousUserMixin
from flask import Flask, jsonify, make_response
from app.extensions import db

class Config_Logs(db.Model):
    __tablename__ = "Config_Logs"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    creation_timestamp = db.Column(db.String, nullable=False)
    config = db.Column(db.String, nullable=False)

    def to_dict(self):
        return {
            "id":self.id,
            "timestamp":self.creation_timestamp,
            "config":self.config
        }
