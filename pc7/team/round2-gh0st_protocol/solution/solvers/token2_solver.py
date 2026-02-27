#!/usr/bin/env python3
# token2_solver.py
import socket, time
s = socket.socket(); s.connect(("gh0st-protocol", 4000)) # Target
time.sleep(0.05); s.recv(4096)     # banner
s.sendall(b"\xAC"); time.sleep(0.05); s.recv(4096)

payload = b"\xBB" + b"\xDE\xAD" + b"\x00\x00\x00\x00"
s.sendall(payload)
time.sleep(0.1)
print(s.recv(4096).decode(), end="")  # SESSION ACCEPTED + TOKEN2
s.close()