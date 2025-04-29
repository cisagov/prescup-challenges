#!/usr/bin/python3

# Basic TCP socket server
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

host = '10.2.2.50'
port = 8888

s.bind((host, port))
s.listen(5)

while True:
    c, addr = s.accept()
    print("Connected to %s" % str(addr))
    while True:
        data = c.recv(1024)
        if not data:
            break
        print("Received: %s" % data.decode())
    c.close()