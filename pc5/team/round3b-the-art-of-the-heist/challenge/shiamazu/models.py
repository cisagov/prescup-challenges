#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from extensions import db


class pin(db.Model):
    __tablename__ = 'Pin'
    username = db.Column(db.String, primary_key=True, nullable=False)
    pin = db.Column(db.String, nullable=False)

