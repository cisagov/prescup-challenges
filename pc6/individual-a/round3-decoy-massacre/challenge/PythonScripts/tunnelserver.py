import socket
from cryptography.fernet import Fernet

key = b'2dU9vXBZaEOU5Zfexy8pGg0T7m7xaFgPE87DhB8w0nE='  # Replace with your actual key
cipher = Fernet(key)

# Set up the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 80))  # Listening on all IPs, port 80
server_socket.listen(5)

print("Server is listening on port 80...")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address} established!")

    try:
        # Receive encrypted message
        encrypted_message = client_socket.recv(1024)
        if encrypted_message:
            # Decrypt the message
            decrypted_message = cipher.decrypt(encrypted_message)
            print(f"Decrypted message: {decrypted_message.decode()}")

            # Send success response back to client
            client_socket.sendall(b"Success")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
