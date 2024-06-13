#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, traceback, secrets, random
from flask import Flask, jsonify
from extensions import db
from models import pin

def check_existing(un):
    chk_user = pin.query.filter_by(username=un).first()
    if chk_user == None:
        return False
    return True

def create_pin(new_username):
    if check_existing(new_username):
        return jsonify({"error":'Username entered already has a pin assigned to it'}),400 
    new_pin = "".join(random.choice("0123456789ABCDEF") for _ in range(4))
    new_user = pin(username=new_username,pin=new_pin)
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error":'Exception occured during request.If error persists contact support',"details":str(e)}),400 
    return f"Pin created for user:\t {new_user.username}.\nPin:\t{new_user.pin}"


def verify_pin(req_un, req_pin):
    try:
        user = pin.query.filter_by(username=req_un).first()
        if user == None:
            return jsonify({"error":'Unable to find record with that username'}),400
    except Exception as e:
        print(f"EXCEPTION:\t {str(e)}")
        return jsonify({"error":'Exception occured during request.If error persists contact support'}),400            
    else:
        if user.pin.lower() == req_pin.lower():
            return "Success"
        return "Failure"
        

def create_app():
    app = Flask(__name__) 
    app.config['SECRET_KEY'] = 'NOT_A_TOKEN' 
    app.config['ACCEPTED_IP'] = ['10.7.7.7','10.5.5.5','10.3.3.52','127.0.0.1']
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'pin.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
    
    from main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    db.init_app(app) 
    with app.app_context():
        db.create_all()
    return app
