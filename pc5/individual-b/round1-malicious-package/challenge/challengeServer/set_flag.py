#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import paramiko, subprocess, time

time.sleep(60)
pickedFlag=subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.pod_access'", shell=True, capture_output=True)
ssh = paramiko.SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("10.3.3.10", 22, username="user", password="N0Ttartans")
transport = ssh.get_transport()
session = transport.open_session()
session.set_combine_stderr(True)
session.get_pty()
session.exec_command("sed -i 's/REVERSE_FLAG/{}/' /home/user/default/tools/python-configmap.yaml\n".format(pickedFlag.stdout.decode().strip('\n')))
stdin = session.makefile('wb', -1)
stdout = session.makefile('rb', -1)
stdin.close()
session.close()
session = transport.open_session()
session.set_combine_stderr(True)
session.get_pty()
session.exec_command("sudo kubectl apply -f /home/user/default/tools/python-configmap.yaml\n")
stdin = session.makefile('wb', -1)
stdout = session.makefile('rb', -1)
time.sleep(2)
stdin.write("sudo kubectl apply -f /home/user/default/tools/python-configmap.yaml\n")
stdin.flush()
time.sleep(2)
stdin.write('N0Ttartans'+'\n')
stdin.flush()
print(stdout.read())
stdin.close()
