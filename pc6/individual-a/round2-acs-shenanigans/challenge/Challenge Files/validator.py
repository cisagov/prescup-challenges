import socket
import time
import os

# Load the specific line (line 19) from the Wiegand data file
def load_target_wiegand_data(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        if len(lines) >= 19:
            return lines[18].strip()  # Line 19 (0-based index)
        else:
            raise ValueError("The file does not contain enough lines.")

valid_wiegand_data = load_target_wiegand_data('/home/user/target_wiegand_data.txt')

# Wait for acs.txt to exist
while not os.path.exists('acs.txt'):
    print("Waiting for acs.txt to be created...")
    time.sleep(10)

# Read the content of acs.txt
with open('acs.txt', 'r') as file:
    acs_content = file.read().strip()

# Use the content of acs.txt as the variable
location = acs_content

# Set up the UDP server
UDP_IP = "0.0.0.0"  # Localhost, change if needed
UDP_PORT = 8081

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening for Wiegand data on {UDP_IP}:{UDP_PORT}...")

# Function to validate Wiegand data against the predefined list
def is_valid_wiegand_data(data):
    return data == valid_wiegand_data

# Extract user ID from Wiegand data
def extract_user_id(data):
    return int(data[10:25], 2)

# Server loop
while True:
    data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
    data = data.decode('ascii')  # Decode the received data to a string

    user_id = extract_user_id(data)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    # Validate the Wiegand data
    if is_valid_wiegand_data(data):
        response = (
            f"[INFO] Access Granted - User ID: {user_id}.\n"
            f"[INFO] {location} Door Unlocked. Event Logged @ {timestamp}."
        )
        print(f"Valid Wiegand data received from {addr}: {data}")
    else:
        response = (
            f"[INFO] Access Denied - User ID: {user_id}.\n"
            f"[INFO] Event Logged @ {timestamp}."
        )
        print(f"Invalid Wiegand data received from {addr}: {data}")

    # Send response back to the player
    sock.sendto(response.encode('ascii'), addr)

