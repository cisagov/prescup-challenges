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

class Anonymous(AnonymousUserMixin):
    id = 0
    name = 'Anon'
    username = 'Anon'
    email = ''
    password = ''
    role = 'ghost'  #None

class Post(db.Model, fs_mixin):
    __tablename__ = 'Post'
    id = db.Column(db.Integer, primary_key=True)
    user_id = str(Anonymous.id)
    user_username = str(Anonymous.username)
    title = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)
    created = db.Column(db.String, nullable=False)

    __fs_fields__ = ['user_id','user_username','title','body'] 

    def __repr__(self):
        return '<Post %r %r %r %r>' % (self.user_id, self.user_username, self.title, self.body)


class Comment(db.Model, fs_mixin):
    __tablename__ = 'Comment'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("Post.id"))
    user_id = str(Anonymous.id)
    author = str(Anonymous.username)
    body = db.Column(db.String, nullable=False)
    created = db.Column(db.String, nullable=False)

    __fs_fields__ = ['post_id','author','body']

    def __repr__(self):
        return '<Comment %r %r %r>' % (self.post_id, self.author, self.body)

class File(db.Model, fs_mixin):
    __tablename__ = 'File'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    user_id = str(Anonymous.id)
    user_username = str(Anonymous.username)
    role = str(Anonymous.role)
    blob = db.Column(db.VARCHAR(10000000), nullable=False)
    uploaded = db.Column(db.String, nullable=False)

    __fs_fields__ = ['name', 'user_id', 'user_username','blob', 'role']

    def __repr__(self):
        return '<File %r %r %r %r %r>' % (self.name, self.user_id, self.user_username, self.blob, self.role)
