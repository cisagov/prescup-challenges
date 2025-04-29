import socket, subprocess
from encryptor import cbc_encrypt

cryptokey = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.cryptokey'", shell=True, capture_output=True).stdout.decode('utf-8').strip()

PORT = 1337
KEY = bytes.fromhex(cryptokey) if len(cryptokey) == 8 else cryptokey.encode("utf-8")[:4]

def start_udp_server():
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind(('0.0.0.0', PORT))
  print(f"UDP server is listening on port {PORT}")
  print(f"Key: {KEY.hex()}")

  while True:
    data, addr = server_socket.recvfrom(1024)
    ip_address = socket.inet_aton(addr[0])
    print(f"Received message from {addr}: {data.hex()}")
    print(f"IV: {ip_address.hex()}")
    ciphertext = cbc_encrypt(data, KEY, ip_address)
    server_socket.sendto(ciphertext, addr)

if __name__ == "__main__":
  start_udp_server()