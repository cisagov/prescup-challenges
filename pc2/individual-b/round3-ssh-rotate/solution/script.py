
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import socket
import sys
import threading
import paramiko
import time

if len(sys.argv) != 2:
    print("Need private host RSA key as arg.")
    sys.exit(1)

host_key = paramiko.RSAKey(filename=sys.argv[1])

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_publickey(self, username, key):
        print(username)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        print(username, password)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_exec_request(self, channel, command):
        print(command)
        self.event.set()
        return True

def listener():
    print("got to point 3333")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 22))

    print('got to point 4444')

    sock.listen(100)
    print('got to point 5555')
    client, addr = sock.accept()

    t = paramiko.Transport(client)
    t.set_gss_host(socket.getfqdn(''))
    t.load_server_moduli()
    t.add_server_key(host_key)
    server = Server()
    t.start_server(server=server)

    server.event.wait(30)
    t.close()

try:
    listener()
except KeyboardInterrupt:
    sys.exit(0)
except Exception as e:
    print(e)
time.sleep(2)
