#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask, request, Response, jsonify, Blueprint, current_app
from __init__ import db
from models import Sensor
import globals
import json, datetime, threading, multiprocessing, time

main = Blueprint('main',__name__)

def change_temp(sensor_id):
    cur_sensor = Sensor.query.filter_by(id=int(sensor_id)).first()
    next_temp = int()
    while True:
        if cur_sensor.curr_temp == cur_sensor.set_temp:
            break
        elif cur_sensor.curr_temp > cur_sensor.set_temp:
            next_temp = cur_sensor.curr_temp - 1
        else:
            next_temp = cur_sensor.curr_temp + 1
        new_time = datetime.datetime.today().strftime('%M:%H, %m-%d-%Y')
        cur_sensor.curr_temp = next_temp
        cur_sensor.last_update = new_time
        db.session.commit()
        time.sleep(1)
        
            

@main.route('/', methods=['GET','POST'])
def index():
    # Check if request is from API
    if request.remote_addr not in current_app.config['ACCEPTED_IP']:
        return "Unauthorized IP detected."
    
    # Check if data sent as POST
    if request.method == 'GET':
        rsp = Sensor.fs_get_delete_put_post()
        rsp2 = json.loads(rsp.data.decode('utf-8'))
        return json.dumps(rsp2, indent=2) #Sensor.fs_get_delete_put_post()
    
    # Verify data passed as json
    try:
        data = request.json
    except Exception as e:
        return "Data not in correct JSON format and/or missing correct headers. Please verify input and try again"

    # Return sensor status
    if data['action'] == 'search':
        try:
            chk = Sensor.query.filter_by(id=int(data['id'])).first()
        except Exception as e:
            return "error: Sensor ID must be Integer. Please verify input and try again."
        if chk == None:
            return "error: no sensor found with passed ID."
        if chk.online == False:
            return "error: Sensor offline"
        try:
            tmp = Sensor.fs_json_get(int(data['id']))
            resp = json.loads(tmp.data.decode('utf-8'))
            return json.dumps(resp, indent=2)
        except Exception as e:
            return "error: Sensor ID incorrect or not present"
    elif data['action'] == 'add':
        if request.remote_addr == '10.7.7.7':
            return "Unable to add new sensor, storage full."
        added = datetime.datetime.today().strftime('%M:%H, %m-%d-%Y')
        data_keys = list(data.keys())
        if ('temp' not in data_keys) or ('overheat' not in data_keys) or ('name' not in data_keys):
            return "Required values for adding sensors missing. Please verify 'temp', 'overheat' and 'name' are present and try again."
        sen_name = data['name']
        temp = int(data['temp'])
        oh = int(data['overheat'])
        new_sensor = Sensor(name=sen_name, curr_temp=temp, set_temp=temp, overheat=oh, last_update=added, online=True)
        try:
            db.session.add(new_sensor)
            db.session.commit()
        except Exception as e:
            return "error: Unable to add sensor."        #str(e) #"error: Unable to add new sensor"
        return "Sensor added"
    
    elif data['action'] == 'update':
        try:
            cur_sensor = Sensor.query.filter_by(id=int(data['id'])).first()
        except Exception as e:
            return "error: Sensor ID must be Integer. Please verify input and try again."
        if cur_sensor is None:
            return "error: Sensor ID incorrect or not present"
        elif cur_sensor.online == False:
            return "error: Sensor offline"
        keys = list(data.keys())
        new_time = datetime.datetime.today().strftime('%M:%H, %m-%d-%Y')
        new_name = data['name'] if 'name' in keys else cur_sensor.name
        new_temp = int(data['temp']) if 'temp' in keys else cur_sensor.set_temp
        try:
            cur_sensor.name = new_name
            cur_sensor.set_temp = new_temp
            cur_sensor.last_update = new_time
            db.session.commit()
        except Exception as e:
            return "Unable to update sensor" # e
        if cur_sensor.curr_temp != new_temp:
            if (data['id'] in list(globals.thread_tracker.keys())) and (globals.thread_tracker[data['id']] != None):
                if globals.thread_tracker[data['id']].is_alive():
                    globals.thread_tracker[data['id']].terminate()
            cur_proc = multiprocessing.Process(target=change_temp,args=(data['id'],))
            cur_proc.start()
            globals.thread_tracker[data['id']] = cur_proc
        return "Sensor Updated"
    
