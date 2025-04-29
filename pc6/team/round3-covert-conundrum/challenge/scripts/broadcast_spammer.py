import socket
import random
import time

# Configuration
BROADCAST_IP = "255.255.255.255"  # Broadcast IP address
PORT = 5005  # Target port
INTERVAL = 0.1  # Interval between packets in seconds (adjust to prevent overload)

try:
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print(f"Sending broadcast packets to {BROADCAST_IP}:{PORT}...")

    while True:
        # Generate a random number
        random_number = random.randint(0, 1000000)

        # Convert the number to bytes and send it as a UDP broadcast packet
        message = str(random_number).encode('utf-8')
        sock.sendto(message, (BROADCAST_IP, PORT))

        print(f"Sent: {random_number}")

        # Wait for the specified interval
        time.sleep(INTERVAL)

except KeyboardInterrupt:
    print("\nBroadcasting stopped.")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    sock.close()


# on APP SERVER