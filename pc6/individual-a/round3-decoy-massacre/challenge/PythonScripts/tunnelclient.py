import socket
import time
from cryptography.fernet import Fernet


while True:
    # Use the same key as the server
    key = b'2dU9vXBZaEOU5Zfexy8pGg0T7m7xaFgPE87DhB8w0nE='  # Replace with your actual key
    cipher = Fernet(key)

    # Set up the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server at localhost on port 80
    server_address = ('10.1.1.30', 80)
    client_socket.connect(server_address)

    # Message to be sent
    message = "Hello, Server! Un8JG@.dA7ZxDvH-9"

    try:
        # Encrypt the message
        encrypted_message = cipher.encrypt(message.encode())

        # Send the encrypted message
        client_socket.sendall(encrypted_message)

        # Receive the response from the server
        response = client_socket.recv(1024)
        print(f"Response from server: {response.decode()}")

        # Wait for 5 seconds before sending the next message
        time.sleep(5)

    except KeyboardInterrupt:
        print("Client stopped by user.")

    finally:
        client_socket.close()
