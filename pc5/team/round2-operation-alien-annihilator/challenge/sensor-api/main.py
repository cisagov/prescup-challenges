#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask, request, Response, jsonify, Blueprint, current_app
import globals
import json, datetime, threading, multiprocessing, time, requests

main = Blueprint('main',__name__)


def authorize(key):
    test = key % 7
    if test == 0:
        return True
    return False


@main.route('/', methods=['GET','POST'])
def index():
    if request.method == 'GET':
        return "Unauthorized attempt. Please pass Key to access."
    
    # Verify data passed as json
    try:
        data = request.json
    except Exception as e:
        return "Data missing header or not in JSON format."

    status = authorize(int(data['key']))
    if status == False:
        return "Incorrect Key."
    
    search = data['search']

    chk = requests.post('http://10.3.3.52:5000', json=search, headers = {"Content-Type":"application/json"})
    return chk.text
    
