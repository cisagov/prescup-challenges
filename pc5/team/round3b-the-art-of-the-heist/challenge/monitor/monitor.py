#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, subprocess, json, requests, ipaddress, datetime, time
from apscheduler.triggers.date import DateTrigger
from requests.auth import HTTPBasicAuth

def check_ip(cur_ip):
    ip = ipaddress.IPv4Address(cur_ip)
    bad_subnet = ipaddress.IPv4Network('10.5.5.0/24')
    if ip in bad_subnet:
        return False
    return True


def monitor():
    req_auth = HTTPBasicAuth("gold","roger")
    url = "http://vault.merch.codes/scheduler/jobs"
    try:
        resp = requests.get(url,auth=req_auth)
    except Exception as e:
        print("cant make connection")
        return
    jobs = json.loads(resp.text)
    jobs_to_cancel = list()
    #print(json.dumps(output,indent=2))
    for job in jobs:
        if job['name'] == "restart_timer":
            continue
        ip_chk = check_ip(job['name'])
        if ip_chk == False:
            jobs_to_cancel.append(job['id'])

    if len(jobs_to_cancel) == 0:
        print("no bad jobs")
        return
    run_time = datetime.datetime.now() + datetime.timedelta(seconds=5)
    trigger_str = run_time.strftime("%Y-%m-%d %H:%M:%S")
    job_request = {
        "id": "remove_clients",
        "func":"app.functions:unauthorized_clients",
        "args":jobs_to_cancel,
        "trigger": "date",
        "run_date": trigger_str,
        "timezone": "America/New_York"
    }

    try:
        resp = requests.post('http://vault.merch.codes/scheduler/jobs', json=job_request, auth=req_auth)
    except Exception as e:
        print(str(e))
    else:
        print(resp.text)

if __name__ == '__main__':
    while True:
        try:
            monitor()
        except Exception as e:
            print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} -- Error occured. Continuing')
        finally:
            time.sleep(30)
