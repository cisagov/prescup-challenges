#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import json, datetime, threading, multiprocessing, time,requests
from flask import Flask, request, Response, jsonify, Blueprint, current_app, render_template, render_template_string
from app.extensions import db
import app.globals as globals
from app.functions import update_config, check_key

main = Blueprint('main',__name__)

@main.route('/', methods=['GET','POST'])
def index():
    return jsonify(globals.config)
    #return render_template_string(globals.home_page)


@main.route('/update-server-pointer',methods=['POST'])
def update_server():
    if globals.timeout['status'] == True:
        if datetime.datetime.now() > globals.timeout['end_time']:
            globals.timeout['status'] = False
        else:
            return jsonify({"Info":f"Rate Limit is {globals.timeout['timer'].seconds} seconds for failed POST attempt."})
    data = request.json
    if 'update_key' not in list(data.keys()):
        return jsonify({"Info":"'update_key' required for updates."})
    elif "server_url" not in list(data.keys()):
        return jsonify({"Error":"'server_url' required to update device config to point to new server."})
    elif "server_port" not in list(data.keys()):
        return jsonify({"Error":"'server_port' required to update device config to point to new server."})
    elif "device_endpoint" not in list(data.keys()):
        return jsonify({"Error":"'device_endpoint' required to update device config to point to new server."})
    
    status, msg = check_key(data['update_key'].strip('\n'))
    if status == False:
        globals.timeout['status'] = True
        globals.timeout['end_time'] = datetime.datetime.now() + globals.timeout['timer']
        return jsonify(msg)
    tmp_url = data['server_url'] if data['server_url'].startswith("http://",0,6) else f"http://{data['server_url']}"
    new_url = tmp_url.rstrip('/')
    try:
        url = f"{new_url}:{data['server_port']}/{data['device_endpoint']}"
        resp = requests.get(url,timeout=(2,2))
    except requests.ConnectTimeout:
        #os.system(f"echo 'fail' > {globals.shared_file}")
        return jsonify({"Error":f"Could not connect to submitted server URL: {url}"})
    except requests.ReadTimeout:
        #os.system(f"echo 'fail' > {globals.shared_file}")
        return jsonify({"Error":f"Did not get request from submitted server URL: {url}"})
    except Exception as e:
        #os.system(f"echo 'fail' > {globals.shared_file}")
        print(f"Requests Error:\t{str(e)}")
        return jsonify({"Error":f"Requests Error: {str(e)}"})
    else:
        if (new_url != globals.update_server) or (data['server_port'] != globals.update_server_port):
            return jsonify({"Error":"Invalid Server URL submitted"})
        tmp_endpoint = data['device_endpoint'].strip("/")
        globals.config['config']['endpoint'] = f"/{tmp_endpoint}"
        try:
            version_url = f"{new_url}:{data['server_port']}{globals.config['config']['endpoint']}/config"
            resp2 = requests.get(version_url)
        except Exception as e:
            return jsonify({"Error":str(e)})
        
        data2 = resp2.content.decode('utf-8')
        try:
            data_dict = json.loads(data2)
        except Exception as e:
            print(f"Error when parsing Json from update server:{update_server}. message:{str(e)}")
            return jsonify({"Error":"Did not get valid JSON Response from update Server"})
        try:
            if 'current_version' in list(data_dict.keys()):
                globals.config['device_info']['version'] = data_dict['current_version']
                globals.config['device_info']['location'] = 'lab'
                globals.config['device_info']['type'] = 'sensor'
            update_config()
            return jsonify({"status":"Device Config Updated"})
        except Exception as e:
            return jsonify({"Error":str(e)})
