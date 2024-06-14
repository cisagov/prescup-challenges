
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import socket, subprocess, threading

server_ip = '0.0.0.0'
server_port = 31337

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind((server_ip, server_port))

server_socket.listen(1)

print(f"Server is listening on {server_ip}:{server_port}")
token = "8160ae" #This can be changed to a different static value or to use a dynamic value 

def handle_client(client):
	while True:
		data = client.recv(1024).decode()
		if data:
			print(f"Received from client: {data}")
			client.send(f"token: {token}\n".encode())
			break
	client.close()

def accept_client():
	while True:
		try:
			client_socket, client_address = server_socket.accept()
			print(f"Accepted connection from {client_address}")
			client_handler = threading.Thread(target=handle_client, args=(client_socket,))
			client_handler.start()
		except socket.error:
			pass
accept_client()
