#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, json, traceback
from flask import request, Blueprint, current_app, render_template, jsonify
from models import pin
from extensions import db
from funcs import verify_pin, create_pin

main = Blueprint('main',__name__)

@main.route('/', methods=['GET','POST'])
def index():
    if request.method == 'GET':
        return render_template('home.html')
    else:
        if 'Content-Type' not in request.headers:
            return jsonify({"error":"'Content-Type: application/json' header missing"}),400
        elif request.headers["Content-Type"] != 'application/json':
            return jsonify({"error":"json mimetype incorrect and/or missing"}),400
        data = request.data.decode('utf-8')
        if len(data) == 0:
            return jsonify({"error":'No JSON data found'}),400
        try:
            data = request.get_json()
        except Exception as e:
            return jsonify({"error":'Failed to parse JSON data','details':str(e)}),400
        
        if 'function' not in list(data.keys()):
            return jsonify({"error":'Function to call missing.'}),400

        if data['function'].lower() == 'verify':
            try:
                resp = verify_pin(data['username'], data['pin'])
                return resp
            except Exception as e:
                traceback.print_exc()
                return jsonify({"error":'Failed to verify pin. Please verify required data is in request and try again'}),400
        elif data['function'].lower() == 'create':
            try:
                resp = verify_pin(data['auth_username'], data['auth_pin'])
                if resp != "Success":
                    return resp
            except Exception as e:
                traceback.print_exc()
                return jsonify({"error":'Failed to verify pin. Please verify authenticated user data is in request and try again'}),400
            try:
                create_resp = create_pin(data['new_user_username'])
                return create_resp
            except Exception as e:
                return jsonify({"error":'New user username missing from request'}),400
        else:
            return jsonify({"error":'Unknown function passed. Please check input and try again'}),400
        
