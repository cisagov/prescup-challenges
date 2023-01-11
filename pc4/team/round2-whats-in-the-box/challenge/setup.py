#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys, subprocess, os, time, datetime, pexpect, json, secrets, random
    

def setup():
    transformVals = dict()
    p = random.randint(20000,60000)
    fi = random.choice("/etc/zsh/zprofile", "/etc/ssl/kali.cnf", "/boot/grub/grub.cfg", "/boot/firmware/config.txt", "/root/.cache/zcompdump")
    pwdList = random.choices(['P0rtT0r7ugA', 'B1AckP3ar1', 'Du7chMaNn', 'Br1ngM3H0r1zen', 'PaR1ayY!!', 'G0dde55Ca1yps0', 'Br3th3rnC0ur7'],k=3)
    
    # pwd for FTPTransfer
    transformVals['transfer.py'] = ['#fpwd',pwdList[0].strip('\n')]
    # portlist
    transformVals['srvr.py'] = [['#port',p],['#file',fi]]
    # username, pwd, scppwd
    transformVals['encrypt.py'] = ['#pwd',pwdList[1].strip('\n')]
    # sshpwd
    transformVals['executor.py'] = ['#sshpwd',pwdList[2].strip('\n')]

    # import transforms into scripts
    for k,v in transformVals.items():
        if type(v[0]) == list:
            for i in v:
                subprocess.run(f"sudo sed -i \"s|{i[0]}|{i[1]}|g\" scripts/{k}",shell=True)
        else:
            subprocess.run(f"sudo sed -i \"s|{v[0]}|{v[1]}|g\" scripts/{k}",shell=True)

    # begin obfusccating & putting into hosted_files directory
    files = sorted(os.listdir('/home/user/challengeServer/setup/'))
    files.remove('tmp')
    output = dict()
    for f in range(0,len(files)):
        scriptNum = f+1
        if scriptNum == 3:
            scriptNum = 5
        elif scriptNum == 5:
            scriptNum = 3
        subprocess.run(f"echo 'Script{scriptNum} is: {files[f]}' | tee -a setupNotes",shell=True,capture_output=True)
        output[f's{scriptNum} cp'] = subprocess.run(f"cp scripts/{files[f]} tmp/script{scriptNum}.py",shell=True,capture_output=True)
        output[f's{scriptNum} armor'] = subprocess.run(f"cd tmp && sudo -u user pyarmor o --exact script{scriptNum}.py",shell=True,capture_output=True)
        output[f's{scriptNum} zip'] = subprocess.run(f"cd tmp && sudo zip -r -m ../hosted_files/script{scriptNum}.zip dist",shell=True,capture_output=True)
    
    with open('armorStatus', 'a+') as f:
        for k,v in output.items():
            f.write(f"cmd:\t{k}\n")
            f.write(f"\nstdout:\n{v.stdout.decode('utf-8')}\n")
            f.write(f"\nstderr:\n{v.stderr.decode('utf-8')}\n")

            
if __name__ == '__main__':
    setup()

