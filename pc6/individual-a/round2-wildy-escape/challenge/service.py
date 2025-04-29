import socket

def start_server(host="0.0.0.0", port=9090):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        # Send scan instructions
        message = "SCAN NETWORK: 10.5.5.0/24"
        client_socket.sendall(message.encode())
        print(f"Scan instructions sent to {addr}")

        # Close connection
        client_socket.close()
        print(f"Connection with {addr} closed.\n")

if __name__ == "__main__":
    start_server()
# On Callisto