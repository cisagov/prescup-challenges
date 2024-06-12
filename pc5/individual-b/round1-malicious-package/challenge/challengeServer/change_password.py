#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import paramiko, subprocess

pickedPassword=subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.pip_pass'", shell=True, capture_output=True)
ssh = paramiko.SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("10.1.1.51", 22, username="user", password="sp@mk1ng")
ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("devpi login root --password=N0Ttartans")
print(ssh_stdout.read())
ssh_stdin.close()
ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("devpi user -m emailAdmin password=" + pickedPassword.stdout.decode().strip('\n'))
print(ssh_stdout.read())
ssh_stdin.close()
