#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import subprocess
import paramiko
from paramiko import *


def grade_challenge():
    results = {}

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect("192.168.0.1", username="vyos", password="vyos")
        stdin, stdout, stderr = ssh.exec_command("cat /config/config.boot")
        lines = stdout.readlines()

        var=False
        for i in range(len(lines)):
            if "rule 1 " in lines[i]:
                if "action accept" in lines[i+1]:
                    var=True
        if var:
            results['Firewall_Check'] = "Failure -- The firewall is not reverted to the previous state"
        else:
            if [True for string in lines if "rule 10" in string]:
                results['Firewall_Check'] = "Success -- The firewall has been reverted"
            else:
                results['Firewall_Check'] = "Failure -- The firewall is not reverted to the previous state"
    except:
        results['Firewall_Check'] = "Failure -- Cannot communicate with the firewall"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect("192.168.0.42", username="User", password="tartans")
        stdin, stdout, stderr = ssh.exec_command("dir C:/Users/User/AppData/Local/Temp")
        lines2 = stdout.readlines()

        var2=True
        for i in lines2:
            if "default.exe" in i:
                var2=False
        if var2:
            results['Breach_Check'] = "Success - Attack artifacts have been removed"
        else:
            results['Breach_Check'] = "Failure -- Attack artifacts are still present"
    except:
        results['Breach_Check'] = "Failure -- Cannot communicate with the system"


    for key, value in results.items():
        print(key, ' : ', value)

if __name__ == '__main__':
    grade_challenge()

