#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, subprocess, requests, json, paramiko

## Configure SH `Required Services` with
# 10.1.1.50 checks for SSH prior to startup
# 10.3.3.19 checks for SSH prior to startup


def setup(data):
    results = dict()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for key in ["0","1","2"]:
        host_info = data[key]
        #results[key] = dict()
        try:
            ssh.connect(host_info['host'],username=host_info['un'],password=host_info['pwd'],timeout=10)
        except paramiko.AuthenticationException:
            results[key] = f"Error: Authentication error occurred during SSH to host {host_info['host']}."
            ssh.close()
            return results
        except Exception as e:
            results[key] = f"Error: Exception occurred during SSH connection -- {str(e)}"
            ssh.close()
            return results
        for index,cmd in enumerate(host_info['cmds']):
            results[key] = dict()
            results[key][index] = dict()
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd,timeout=3)
                resp = [
                    stdout.read().decode().strip(),
                    stderr.read().decode().strip()
                ]
            except Exception as e:
                results[key][index]['cmd_error'] = f"Error: Exception occurred sending command.\ncmd: {cmd}\nException: {str(e)}"
            else:
                results[key][index]['stdout'] = resp[0]
                results[key][index]['stderr'] = resp[1]
        ssh.close()
    return results


if __name__ == "__main__":
    domain = subprocess.run("vmware-rpctool 'info-get guestinfo.domain1'",shell=True,capture_output=True).stdout.decode('utf-8').strip()
    sender = subprocess.run("vmware-rpctool 'info-get guestinfo.sender1'",shell=True,capture_output=True).stdout.decode('utf-8').strip()
    data = {
        "0": {
              "host":"123.45.67.200",
              "un":'user',
              "pwd":'tartans',
              "cmds":[
                  "python3 send_mail.py -s " + sender + " -r tshaw@lab.net -p 25 -S 123.45.67.89 -n 5 -c '{\"subject\":\"You Should Find This\",\"body\":\"This is te answer to the question\"}'"
            ]
        },
        "1": {
            "host": "10.1.1.50",
            "un":"user",
            "pwd":"tartans",
            "cmds":[
                'echo "tartans" | sudo -S bash -c "sed -i \"/^DNS=/c\DNS=10.3.3.10\" /etc/systemd/resolved.conf',
                'echo "tartans" | sudo -S bash -c "systemctl restart systemd-resolved"',
                'echo "tartans" | sudo -S bash -c "ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf"'
            ]
        },
        "2": {
            "host": "10.3.3.10",
            "un":"user",
            "pwd": "tartans",
            "cmds": [
                f'echo "tartans" | sudo -S bash -c "pihole -b {domain}"'
            ]
        }
    }
    res = setup(data)
    with open('/home/user/skillsHub/startup_output.txt', 'w+') as f:
        f.write(json.dumps(res, indent=2))
