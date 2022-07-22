#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import paramiko, sys, os, socket, time
global host, username, line, input_file

hostname = socket.gethostname()
host = socket.gethostbyname(hostname)

username = 'hqbovik'

def ssh_connect ( password, code = 0):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )

	try:
	    ssh.connect( host, port=22, username=username, password=password )
	except paramiko.AuthenticationException:		
	    code = 1	
	except socket.error:
	    code = 2

	ssh.close()
	return code

while True:
	ssh_connect( 'PLACEHOLDER' )
	time.sleep( 10 )

