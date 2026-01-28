#!/usr/bin/env python3
import os
import socket
import struct
import threading
import random
import sys

HOST = "0.0.0.0"
PORT = 9999
TOKEN = os.environ.get("TOKEN3")

ASCII = f"""
\x1b[1;33m 
█▀▀ █▀▀█ █▀▀▄ █▀▀ 　 █▀▀█ █▀▀ ░▀░ █▀▀█ ░▀░ █▀▀ 
█░░ █░░█ █░░█ █▀▀ 　 █░░█ ▀▀█ ▀█▀ █▄▄▀ ▀█▀ ▀▀█ 
▀▀▀ ▀▀▀▀ ▀▀▀░ ▀▀▀ 　 ▀▀▀▀ ▀▀▀ ▀▀▀ ▀░▀▀ ▀▀▀ ▀▀▀
R E M O T E     E X P L O T     T R A I N E R
\x1b[0m
Welcome to Level 3!

This is a simulated network binary challenge. 
Your mission is to CRASH the service, learn where the EIP would be overwritten,
and finally, deliver a special payload that will grant you the token!
"""

HELP = """
Commands:
  HELP         - Show this help.
  BOF          - Send your buffer overflow payload.
  QUIT/EXIT    - Exit this session.

How it works:
- Type BOF to pull up the prompt to exploit
- Information about the remote buffer limits will be provided to you.
- If you overflow the "buffer", you'll see a simulated crash address.

Your goal: 
- Figure out the offset needed to control the EIP (shown as crash address).
- Then, craft a payload to set the crash address to 0xdeadbeef and receive your token!
"""

def handle_client(conn, addr):
    try:
        conn.sendall(ASCII.encode())
        conn.sendall(b"\nType HELP for instructions.\n\n")
        while True:
            conn.sendall(b"\n> ")
            cmd = conn.recv(128).strip().decode(errors="ignore").upper()
            if not cmd:
                break
            if cmd in ("QUIT", "EXIT"):
                conn.sendall(b"Goodbye!\n")
                break
            elif cmd == "HELP":
                conn.sendall(HELP.encode())
            elif cmd == "BOF":
                simulate_bof(conn)
            else:
                conn.sendall(b"Unknown command. Type HELP.\n")
    except Exception as e:
        try: conn.sendall(f"Error: {e}\n".encode())
        except: pass
    finally:
        conn.close()

def simulate_bof(conn):
    """
    Simulate classic buffer overflow:
    - User must send exactly 209 bytes: 201 filler, 4 NOPs, 4 bytes for EIP.
    - If only 201 bytes: print the simulated EIP overwrite (the next 4 bytes).
    - If >201 and <209: too few; if >209: too many.
    - If the "NOP sled" is not correct, or EIP is not 0xdeadbeef, print a simulated crash.
    """
    conn.sendall(b"\n[+] Enter your buffer as raw bytes (e.g. 'AAAAAA'):\n")
    conn.sendall(b"YOUR BUFFER > ")

    # Receive up to 209 bytes
    data = b""
    while len(data) < 209:
        chunk = conn.recv(209 - len(data))
        if not chunk:
            break
        data += chunk
        if b"\n" in chunk:
            data = data.split(b"\n",1)[0]
            break

    total_len = len(data)
    if total_len < 201:
        conn.sendall(b"Not enough bytes to reach EIP! Try again.\n")
        return
    elif total_len == 201:
        # Show the next 4 bytes as EIP
        fake_eip = b'\x9d\x3a\xd3\xaf'
        conn.sendall(f"\n[DEBUG] Buffer received: {total_len} bytes.\n".encode())
        conn.sendall(f"[DEBUG] Simulated EIP: 0x{struct.unpack('<I', fake_eip)[0]:08x}\n".encode())
        conn.sendall(b"You're at the right offset! Now try again, and after your 201 bytes, send 4 NOPs (\\x90) and then 0xdeadbeef in the right networking format.\n")
        return
    elif total_len > 201 and total_len < 209:
        conn.sendall(f"Too few bytes for this exploit! You need exactly 209 bytes (201 filler + 4 NOPs + 4 EIP).\n".encode())
        return
    elif total_len > 209:
        conn.sendall(f"Too many bytes! Only 209 bytes are accepted.\n".encode())
        return

    # Now, data length == 209
    buf = data[:201]
    nops = data[201:205]
    eip = data[205:209]

    if nops != b'\x90\x90\x90\x90':
        conn.sendall(b"[CRASH] Program crashed! But you need 4 NOPs (\\x90) after your buffer before EIP.\n")
        return

    if eip == struct.pack("<I", 0xdeadbeef):
        conn.sendall(b"\n\x1b[1;32m[WIN] Congratulations! You've overwritten EIP after your NOP sled.\x1b[0m\n")
        conn.sendall(f"TOKEN3: {TOKEN}\n".encode())
        conn.sendall(b"Session closing. Try again to practice!\n")
    else:
        conn.sendall(b"\x1b[1;31m[CRASH] Program crashed at address: 0x" + b"%08x" % struct.unpack("<I", eip) + b"\x1b[0m\n")
        conn.sendall(b"Remember: you need 4 NOPs after your buffer and EIP set to 0xdeadbeef!\n")

        

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(8)
        print(f"[+] Listening on {HOST}:{PORT}")
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except KeyboardInterrupt:
                print("\nShutting down.")
                break

if __name__ == "__main__":
    main()

