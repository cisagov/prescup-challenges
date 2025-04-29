...

def cbc_encrypt(plaintext, key, iv):
    block_size = len(iv)
    if len(key) != block_size:
        raise ValueError("Key length must match block size (IV length).")

    plaintext = pad(plaintext, block_size)
    ciphertext = b""
    previous_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        encrypted_block = xor_bytes(block, previous_block)
        encrypted_block = xor_bytes(encrypted_block, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext

def start_udp_server():
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind(('0.0.0.0', PORT))
  print(f"UDP server is listening on port {PORT}")

  while True:
    data, addr = server_socket.recvfrom(1024)
    ip_address = socket.inet_aton(addr[0])
    print(f"Received message from {addr}: {data.hex()}")
    ciphertext = cbc_encrypt(data, KEY, ip_address)
    server_socket.sendto(ciphertext, addr)