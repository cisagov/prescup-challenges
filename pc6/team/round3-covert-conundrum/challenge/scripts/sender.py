import os
import socket
import time

def send_file(file_path, server_ip, server_port, sentinel_word="ErrorSending"):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()


        sentinel_data = sentinel_word.encode('utf-8')

        data = sentinel_data + file_data
        # Create a socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_ip, server_port))
            client_socket.sendall(data)
            print(f"File '{file_path}' sent to {server_ip}:{server_port}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    FILE_DIR = "/data"  # Replace with the file path to send
    SERVER_IP = "123.45.67.100"  # Replace with the remote machine's IP
    SERVER_PORT = 54  # Custom port number

    while True:
        for filename in os.listdir(FILE_DIR):
            file_path = os.path.join(FILE_DIR, filename)
            if os.path.isfile(file_path):
                send_file(file_path, SERVER_IP, SERVER_PORT)
                time.sleep(5)  # Wait 5 seconds before sending the file again

