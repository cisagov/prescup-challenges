import socket, subprocess

PORT = 1337
SERVER_IP = "10.5.5.101"
# SERVER_IP = "10.5.5.5"

local_ip = subprocess.run("ip a | grep 10.5.5 | cut -d '/' -f 1 | awk '{print $2}'", shell=True, capture_output=True).stdout.decode('utf-8').strip()
local_ip_bytes = socket.inet_aton(local_ip)

if __name__ == "__main__":
  print(f"IV: {local_ip_bytes.hex()}")
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    plaintext = local_ip_bytes
    sock.sendto(plaintext, (SERVER_IP, PORT))
    ciphertext = sock.recv(1024)
    key = ciphertext[:4]
    print(f"Key: {key.hex()}")