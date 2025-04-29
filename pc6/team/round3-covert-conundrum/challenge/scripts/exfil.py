import socket
import os

def save_file(save_directory, server_port):
    # Create the directory if it doesn't exist
    os.makedirs(save_directory, exist_ok=True)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', server_port))
    server_socket.listen(5)

    print(f"Server listening on port {server_port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        file_data = b""
        while True:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            file_data += chunk

        # Save the received file
        file_path = os.path.join(save_directory, "received_file.txt")
        with open(file_path, 'wb') as file:
            file.write(file_data)
        print(f"File saved to {file_path}")

        client_socket.close()

if __name__ == "__main__":
    SAVE_DIRECTORY = "/home/user/received_files"  # Replace with the desired save location
    SERVER_PORT = 54  # Custom port number

    save_file(SAVE_DIRECTORY, SERVER_PORT)
