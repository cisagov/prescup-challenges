#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os,sys, subprocess, time, random, socket

def startServer(port, chosenDir, f=None):
    if f != None:
        subprocess.run(f"sudo hping3 -q -e 'Target:{socket.gethostname()}:{port}:{f}\n' ext -c 1 -1",shell=True,capture_output=True) 
    tst = subprocess.run(f"sudo bash -c 'python3 -m http.server {port} --directory {chosenDir} >/dev/null 2>&1 &'",shell=True,capture_output=True).stdout.decode('utf-8')

def chkSrvr():
    dirList = list()
    curDirList = subprocess.run("ls -d */",shell=True, capture_output=True)
    if "cannot access" in curDirList.stderr.decode('utf-8'):
        curDirList = subprocess.run("ls -d ../*/",shell=True, capture_output=True).stdout.decode('utf-8').split('\n')
        tmpPwd = subprocess.run("pwd",shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
        pwd = tmpPwd[:tmpPwd.rindex('/')]
        curDirList.remove('')
        for d in curDirList:
            tmpDir = os.path.abspath(d) + '/'
            dirList.append(tmpDir)
    else:
        curDirList = curDirList.stdout.decode('utf-8').split('\n')
        curDirList.remove('')
        pwd = subprocess.run("pwd",shell=True, capture_output=True).stdout.decode('utf-8').strip('\n')
        for d in curDirList:
            tmpDir = os.path.abspath(d) + '/'
            dirList.append(tmpDir)

    if '/root' not in dirList:
        dirList.append('/root')
    if '/etc' not in dirList:
        dirList.append('/etc')
    if '/boot' not in dirList:
        dirList.append('/boot')

    portList = list()
    x = 0
    port = '#port'
    file = '#file'
    while x < len(dirList):
        tmpPort = str(random.randint(20000,60000))
        if port in portList:
            continue
        psOut = subprocess.run("netstat -tulpn",shell=True,capture_output=True).stdout.decode('utf-8')
        if tmpPort not in psOut:
            portList.append(tmpPort)
            x += 1
            continue
    
    for d in dirList:
        if ((d == '/root') or (d == '/etc') or (d == '/boot')) and (d in file):
            startServer(port, d, file)
            continue
        for p in portList:
            if p in subprocess.run("netstat -tulpn",shell=True,capture_output=True).stdout.decode('utf-8'):
                continue
            startServer(p, d)
            portList.remove(p)
            time.sleep(1)
            break

    print(f"{len(dirList)} successfully setup.")

if __name__ == '__main__':
    chkSrvr()
