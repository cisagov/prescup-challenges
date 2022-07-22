#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# this script will run various commands and save their output, write it to a local CSV, then POST the information to the API for storage
# It is meant to be an additional security check that can help IT to notice if there is any suspicious activity on our macines.

import os, re, sys, csv, json, subprocess, logging, time, random
from datetime import datetime
import pandas as pd
import requests

# configure logging for debugging
logging.basicConfig(format='%(asctime)s  %(levelname)s  %(message)s', level=logging.INFO, datefmt='%m/%d/%Y %I:%M:%S %P')

def getInfo():
    logging.info("Begin producing information from commands, return values in dictionary.")
    now=datetime.now()
    date=str(now.strftime("%d/%m/%y %H:%M:%S"))
    id= subprocess.run("for user in $(cat /etc/passwd | cut -f1 -d':'); do id $user; done", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    id= id.replace('\n',' ')
    groups= subprocess.run("for user in $(cat /etc/passwd | cut -f1 -d':'); do groups $user; done", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    finger= subprocess.run("for user in $(cat /etc/passwd | cut -f1 -d':'); do finger $user; done", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    printenv= subprocess.run("printenv", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    lslogins=subprocess.run("lslogins", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    users=subprocess.run("users", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    who= subprocess.run("who", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    w= subprocess.run("w", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    last= subprocess.run("last", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    lastlog= subprocess.run("lastlog", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    ip= subprocess.run("host kali | tail -c 11 | tr -d \\n", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    hostName=subprocess.run("hostname", shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
    
    output=dict()
    output[date] = {
        'ip':str(ip[1:]),
        'host':str(hostName),
        'id':str(id),
        'groups':str(groups),
        'finger':str(finger),
        'printenv':str(printenv),
        'lslogins':str(lslogins),
        'users':str(users),
        'who':str(who),
        'w':str(w),
        'last':str(last),
        'lastlog':str(lastlog)
    }
    
    for x in output:
        if ( len(output[x]) == 0):
            logging.error(f'{x} command did not produce expected results')
    return output

def updateLocalCsv(output):
    logging.info("Begin writing new information to local CSV.")
    pd.DataFrame.from_dict(output, orient='index',columns=['ip','host','id','groups','finger','printenv','lslogins','users','who','w','last','lastlog']).to_csv('~/Desktop/round2-sneaky-snake/challenge/info.csv',index_label='date')
    logging.info("local CSV updated")

def sendUpdate(output):
    logging.info("Begin uploading new information to admin CSV via POST request.")
    data= json.dumps(output)
    headers = {'Content-type':'application/json', 'Accept':'application/json'}
    try:
        req= requests.post('http://api:8080', headers=headers, data=data)
        logging.info(f'POST status code: '+str(req.status_code))
    except Exception:      # might need it to be gaierror, NewConnectionError, or MaxRetyError
        logging.error(f'Post request unable to complete')

if __name__=="__main__":
    # print(sys.path)
    logging.info("Script Started")
    i=0
    while (i==0):       
        output=getInfo()
        updateLocalCsv(output)
        sendUpdate(output)
        time.sleep(random.randint(21600,28800))     # script should auto run & update every 6-8 hours 
