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
    created = None

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)
    created = db.Column(db.String, nullable=False)

class Projects(db.Model):
    __tablename__ = 'Projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    class Past(db.Model):
        __tablename__ = 'Past'
        id = db.Column(db.Integer, primary_key=True)
        customer_name = db.Column(db.String, db.ForeignKey('Projects.name'))
        start_date = db.Column(db.String, nullable=False)
        date_completed = db.Column(db.String, nullable=False)
        price = db.Column(db.String, nullable=False)
        details = db.Column(db.String, nullable=False)

    class Current(db.Model):
        __tablename__ = 'Current'
        id = db.Column(db.Integer, primary_key=True)
        customer_name = db.Column(db.String, db.ForeignKey('Projects.name'))
        start_date = db.Column(db.String, nullable=False)
        projected_end_date = db.Column(db.String, nullable=False)
        projected_price = db.Column(db.String, nullable=False)
        details = db.Column(db.String, nullable=False)

    class Future(db.Model):
        __tablename__ = 'Future'
        id = db.Column(db.Integer, primary_key=True)
        customer_name = db.Column(db.String, db.ForeignKey('Projects.name'))
        projected_start_date = db.Column(db.String, nullable=False)
        projected_price = db.Column(db.String, nullable=False)
        details = db.Column(db.String, nullable=False)

class Auth(db.Model):
    __tablename__='Auth'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String, nullable=False)
