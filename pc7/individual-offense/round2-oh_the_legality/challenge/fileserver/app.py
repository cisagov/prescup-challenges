import socket
import json
import time

BROADCAST_IP = '192.168.5.255'
PORT = 55454
SECRET_KEY = 'ERROR404'

counter = 0

while True:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(1)

            command_data = {
                "key": SECRET_KEY,
                "command": f"echo Data packet {counter}"
            }

            # Convert to JSON and encode to bytes
            message = json.dumps(command_data).encode('utf-8')
            s.sendto(message, (BROADCAST_IP, PORT))

            try:
                data, addr = s.recvfrom(4096)
                print(f"[SERVER RESPONSE from {addr}] {data.decode('utf-8')}")
            except socket.timeout:
                print("[INFO] No response from server, retrying...")

            counter += 1
            time.sleep(1)
    except Exception as e:
        print(f"[ERROR] {e}. Continuing...")
        time.sleep(1)
