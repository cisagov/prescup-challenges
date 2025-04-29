import socket
import time

# Read specific lines (3, 7, 11, 15) from the Wiegand data file
with open('/home/user/target_wiegand_data.txt', 'r') as file:
    lines = file.readlines()
    wiegand_data_list = [lines[i].strip() for i in [2, 6, 10, 14]]  # 0-based index

# UDP broadcast configuration
UDP_IP = "10.5.5.255"  # Broadcast address
UDP_PORT = 8080
BROADCAST_INTERVAL = 30  # Seconds

# Set up UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print("Starting Wiegand traffic broadcast...")
try:
    while True:
        for wiegand_data in wiegand_data_list:
            # Send hardcoded Wiegand data as bytes
            sock.sendto(wiegand_data.encode('ascii'), (UDP_IP, UDP_PORT))
            print(f"Broadcasted: {wiegand_data}")
            time.sleep(BROADCAST_INTERVAL)  # Wait 30 seconds before sending next card data
except KeyboardInterrupt:
    print("Broadcast stopped.")
    sock.close()
