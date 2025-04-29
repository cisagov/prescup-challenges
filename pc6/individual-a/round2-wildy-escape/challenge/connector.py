import socket

def start_shell_client(server_ip, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    print(f"Connected to {server_ip}:{server_port}")

    try:
        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            print(data, end="")

            command = input()
            client_socket.send(command.encode())

            if command.lower() in ["exit", "quit"]:
                break

            response = client_socket.recv(4096).decode()
            print(response, end="")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    server_ip = "10.3.3.3"  # Replace with the server's IP
    server_port = 45136
    start_shell_client(server_ip, server_port)
# On KBDPure