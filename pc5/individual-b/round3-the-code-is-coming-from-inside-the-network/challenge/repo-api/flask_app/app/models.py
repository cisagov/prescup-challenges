
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from app.extensions import db

class Source(db.Model):
    __tablename__='Source'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    remote_path = db.Column(db.String, nullable=False)
    blob = db.Column(db.VARCHAR(10000000), nullable=False)
    last_update = db.Column(db.String, nullable=False)

class Last_update(db.Model):
    __tablename__='Last_update'
    id = db.Column(db.Integer, primary_key=True)
    last_push = db.Column(db.String, nullable=False)
    
class Backup(db.Model):
    __tablename__='Backup'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    remote_path = db.Column(db.String, nullable=False)
    blob = db.Column(db.VARCHAR(10000000), nullable=False)
    last_update = db.Column(db.String, nullable=False)

class Token(db.Model):
    __tablename__='Token'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    hex = db.Column(db.String, nullable=False)

class Auth(db.Model):
    __tablename__="Auth"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String, nullable=False, unique=True)
    get = db.Column(db.String, nullable=False)
    post = db.Column(db.String, nullable=False)
    token = db.Column(db.String, nullable=False, unique=True)
