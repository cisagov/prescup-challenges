#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import random, string
from sqlalchemy import text
from flask_login import UserMixin, AnonymousUserMixin
from app.extensions import db


def generate_id():
    while True:
        id_str = ''.join(random.choices(string.hexdigits[:16].lower(),k=6))
        if db.session.execute(text(f"select * from User where user_id='{id_str}'")).scalar() is not None:
            continue    
        return id_str

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
    user_id = db.Column(db.String, primary_key=True, default=generate_id)
    fname = db.Column(db.String, nullable=False)
    lname = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)
    created = db.Column(db.String, nullable=False)
    notes = db.Column(db.String, nullable=False, default="")
    
    def get_id(self):
        return self.user_id

class User_Conversations(db.Model):
    __tablename__ = 'User_Conversations'
    user_convo_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String, nullable=False)
    convo_id = db.Column(db.Integer, nullable=False)


class Conversations(db.Model):
    __tablename__ = "Conversations"
    convo_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    participants = db.Column(db.String, nullable=False)   
    created = db.Column(db.String, nullable=False)
    

class Messages(db.Model):
    __tablename__ = "Messages"
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    convo_id = db.Column(db.Integer, nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String, nullable=False)
    sent_time = db.Column(db.String, nullable=False)  

class Shop(db.Model): 
    __tablename__ = 'Shop'
    item_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String, nullable=False) 
    desc = db.Column(db.String, nullable=False) 
    price = db.Column(db.String, nullable=False) 

class Categories(db.Model):
    __tablename__ = 'Categories'
    category_id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    category = db.Column(db.String, nullable=False)
    
    def get_dict():
        all_categories = Categories.query.all()
        category_dict = dict()
        for cate in all_categories:
            category_dict[cate.category_id] = cate.category
        return category_dict
            
class Purchase_Receipts(db.Model):
    __tablename__ = 'Purchase_Receipts'
    rid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String, nullable=False) 
    items = db.Column(db.String, nullable=False)
    cost = db.Column(db.String, nullable=False)
    review = db.Column(db.String, nullable=False)
