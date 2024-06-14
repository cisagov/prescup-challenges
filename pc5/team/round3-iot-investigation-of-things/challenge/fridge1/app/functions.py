#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os, yaml, random, datetime, json, requests, string
from app.extensions import *
from app.models import *
import app.globals as globals

## Load device config
def load_config():
    with open(globals.config_fp, 'r') as file:
        try:
            conf = yaml.safe_load(file)
            print("config loaded")
            return conf
        except yaml.YAMLError:
            print("Error Reading config.yaml")
            exit(1)


def update_config():
    with globals.config_lock:
        with open(globals.config_fp, 'w') as file:
            try:
                yaml.dump(globals.config, file)
            except yaml.YAMLError:
                print("Error Writing to config.yaml. Reverting")
                #exit(1)

def alter_temp():
    with scheduler.app.app_context():
        if globals.conf['device_info']['version'] == "3.4.5":
            globals.config['data']['temperature'] = random.randint(60,80)
            globals.config['data']['temperature_value'] = random.choice(list(string.ascii_lowercase))
            globals.config['data']['measurement'] = random.choice(list(string.ascii_lowercase))
        else:
            if globals.config['data']['temperature_value'] in list(string.ascii_lowercase):
                globals.config['data']['temperature'] = 35
                globals.config['data']['temperature_value'] = '3'
                globals.config['data']['measurement'] = 'f'
            if globals.temp_counter == 0:
                ### Below gets temperature in config range list that is not the current. I.e: if value==0 and temperature==32, this will return 33
                #tmp_list = globals.config_ranges['temperature_values'][globals.config['data']['measurement']][globals.config['data']['temperature_value']]
                #tmp_list.remove(globals.config['data']['temperature'])
                #new_temp = tmp_list[0]
                ### Below is 1 line cmd that does the same as block above
                new_temp = next((t for t in globals.config_ranges['temperature_values'][globals.config['data']['measurement']][globals.config['data']['temperature_value']] if t != globals.config['data']['temperature']),None)
                globals.config['data']['temperature'] = new_temp
                globals.temp_counter = 1
            else:
                new_val = random.randint(1,2)
                status = (new_val % 2 == 0)
                if globals.config['data']['temperature_value'] == '0':
                    globals.config['data']['temperature_value'] = '1'                       ##  'temp-value'::'f'::'1':: 
                    globals.config['data']['temperature'] = globals.config_ranges['temperature_values'][globals.config['data']['measurement']][globals.config['data']['temperature_value']][new_val-1]
                elif globals.config['data']['temperature_value'] == '5':
                    globals.config['data']['temperature_value'] = '4'
                    globals.config['data']['temperature'] = globals.config_ranges['temperature_values'][globals.config['data']['measurement']][globals.config['data']['temperature_value']][new_val-1]
                else:
                    if status:
                        #print('raise value')
                        globals.config['data']['temperature_value'] = str(int(globals.config['data']['temperature_value']) + 1)
                        globals.config['data']['temperature'] = globals.config_ranges['temperature_values'][globals.config['data']['measurement']][globals.config['data']['temperature_value']][new_val-1]
                    else:
                        #print('lower value')
                        globals.config['data']['temperature_value'] = str(int(globals.config['data']['temperature_value']) - 1)
                        globals.config['data']['temperature'] = globals.config_ranges['temperature_values'][globals.config['data']['measurement']][globals.config['data']['temperature_value']][new_val-1]
                globals.temp_counter = 0
        update_config()
            

def send_data():
    with scheduler.app.app_context():
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        config_to_upload = globals.config
        #del config_to_upload['config']['change_device_server_pointer']
        config_to_upload['timestamp'] = timestamp
        json_format = json.dumps(config_to_upload)
        try:
            resp = requests.post(globals.cc_url,json=json_format,timeout=(2,2))
        except requests.ConnectTimeout:
            os.system(f"echo 'fail' >> {globals.shared_file}")
            print(f"Could not connect to send request to {globals.cc_url}")
        except requests.ReadTimeout:
            os.system(f"echo 'fail' >> {globals.shared_file}")
            print(f"Did not get request from {globals.cc_url}")
        except Exception as e:
            os.system(f"echo 'fail' >> {globals.shared_file}")
            print(f"Requests Error:\t{str(e)}")
        else:
            os.system(f"echo 'pass' >> {globals.shared_file}")
            print("update sent")


def check_update():
    if datetime.datetime.now() > datetime.datetime.strptime(globals.config['device_info']['next_update'],"%Y-%m-%d %H:%M:%S"):
        try:
            resp = requests.get(f"{globals.update_server}:{globals.update_server_port}/{globals.config['data']['device']}/version",timeout=(1,1))
        except requests.Timeout:
            print(f"Timeout occured while connecting to update server")
        except Exception as e:
            print(f"Error occured:\t{e}")
        else:
            new_date = datetime.datetime.now() + datetime.timedelta(weeks=1)
            try:
                data = json.loads(resp.content)
                if "current_version" not in list(data.keys()):
                    print("Current_version key missing")
                    globals.update_status = "fail"
                    return
                elif globals.config['device_info']['version'] != data['current_version']:
                    print("New version available. Updating...")
                    globals.config['device_info']['version'] = data['current_version']
                    globals.config['device_info']['next_update'] = new_date.strftime('%Y-%m-%d %H:%M:%S')
                    globals.update_status = "pass"
                else:
                    print("Device up to date")
                    globals.config['device_info']['next_update'] = new_date.strftime('%Y-%m-%d %H:%M:%S')
                    globals.update_status = "pass"
            except Exception as e:
                print(f"Error occured while processing update data:\t {str(e)}")
                globals.update_status = "fail"
        update_config()
    else:
        print("Not time for update")

def update_keys():
    ### Keys pattern
    # format:   `letter`+`hex of letter`+`letter`+`hex of letter`
    # start is: `a61Z5A`
    # then we add 1 to 'a' to make `b`, and then capitalize it `B`
    # followed by its hex value
    # then we subtract 1 from Z to make `X` and then lowercase it `x`
    # Followed by its hex value
    # next iteration would be `B42x78`
    # pattern follows that format.
    ###
    current_key = globals.keys['current']
    p1_letter=p2_letter=""

    if current_key[0].lower() == 'z':
        p1_letter = "A" if current_key[0].islower() else 'a'
    else:
        p1_letter = chr(ord(current_key[0]) +1).upper() if current_key[0].islower() else chr(ord(current_key[0]) +1).lower()
    p1_hex = format(ord(p1_letter),'x')

    if current_key[3].lower() == 'a':
        p2_letter = "Z" if current_key[3].islower() else 'z'
    else:
        p2_letter = chr(ord(current_key[3]) -1).upper() if current_key[3].islower() else chr(ord(current_key[3]) -1).lower()
    p2_hex = format(ord(p2_letter),'x')

    #next_key = f"{p1_letter}{p1_hex}{p2_letter}{p2_hex}"
    globals.keys['previous'] = current_key
    globals.keys['current'] = f"{p1_letter}{p1_hex}{p2_letter}{p2_hex}"




def check_key(update_key):
    msg = ()
    if update_key == globals.keys['current']:
        msg = (True,{"Info":"Key Accepted"})
    else:
        msg = (False,{"Error":f"Incorrect key, expecting {globals.keys['current']}"})
    update_keys()
    return msg
