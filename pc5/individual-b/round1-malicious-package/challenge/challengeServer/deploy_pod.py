#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import paramiko, time

ssh = paramiko.SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("10.3.3.10", 22, username="user", password="N0Ttartans")
transport = ssh.get_transport()
session = transport.open_session()
session.set_combine_stderr(True)
session.get_pty()
session.exec_command("sudo kubectl apply -f /home/user/default/tools/python.yaml")
stdin = session.makefile('wb', -1)
stdout = session.makefile('rb', -1)
time.sleep(2)
stdin.write('N0Ttartans'+'\n')
stdin.flush()
print(stdout.read())

