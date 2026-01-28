#!/usr/bin/env python3
import os
import socketserver
import sys
import time
import struct
from datetime import datetime

ascii_art = """
▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░▒▓███████▓▒░ 
▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        
▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        
▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓██████▓▒░  
▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░          ░▒▓█▓▒░     ░▒▓█▓▒░ 
▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░          ░▒▓█▓▒░     ░▒▓█▓▒░ 
▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓███████▓▒░▒▓███████▓▒░ NET
"""

TOKEN4 = os.environ.get("TOKEN4")

def render_terminal_header(wfile):
    now = datetime.utcnow()
    timestamp = now.strftime("%H%MZ %d%b%Y").upper()
    header = f"""
\x1b[1;32m┌──────────────────────────────────────────────────────────────┐
│                     ABYSSNET LAUNCH TERMINAL                  │
├──────────────────────────────────────────────────────────────┤
│  SECURITY LEVEL: ████████░░░░░░  (LVL 3 CLEARANCE)            │
│  STATUS        : ONLINE                                       │
│  SYSTEM TIME   : {timestamp:<44}│
└──────────────────────────────────────────────────────────────┘\x1b[0m
"""
    wfile.write(header.encode())
    wfile.flush()

def socket_main(rfile, wfile):
    def send(text="", end="\n"):
        wfile.write((text + end).encode())
        wfile.flush()

    def recv_line():
        line = rfile.readline()
        if not line:
            return ""
        return line.decode(errors="ignore").strip()

    send(ascii_art)
    render_terminal_header(wfile)
    send("🔐️ SYSTEM LOCKED. ACCESS RESTRICTED TO LEVEL 3 RESEARCHERS ONLY.\n")

    while True:
        try:
            send("> ", end="")
            cmd = recv_line()
            if not cmd:
                send("\n[!] Disconnected.")
                break

            cmd = cmd.upper()
            if cmd == "AUTH":
                send("🔐️ Key is required.")
            elif cmd == "CONNECT":
                send("📔️ No connections available.")
            elif cmd == "LAUNCH":
                send("🚨 LAUNCH SYSTEM ACTIVE 🚨\n")
                send("Enter LAUNCH CODE (max 40 bytes):")

                buf = bytearray(32)
                auth = b'\x00\x00\x00\x00'
                launch_input = rfile.readline().strip()

                for i in range(min(len(launch_input), 32)):
                    buf[i] = launch_input[i]

                overflow = launch_input[32:]
                if len(overflow) >= 8:
                    nops = overflow[:4]
                    new_auth = overflow[4:8]
                    if new_auth:
                        auth = new_auth
                    send(f"[DEBUG] Detected NOP sled: {nops}")
                    send(f"[DEBUG] Overflow Auth: 0x{struct.unpack('<I', auth)[0]:08x}")
                else:
                    send("No valid overflow detected.")

                send(f"📊 Buffer length sent: {len(launch_input)}")

                if auth == b'\x53\x41\x4c\x54':  # 'SALT'
                    send("✅ LAUNCH CODE ACCEPTED. ☣️ NUCLEAR LAUNCH IN 5 SECONDS ☣️")
                    time.sleep(5)
                    send("♠️ OIC: yara.d4nt3\nJust kidding. I can't believe you'd actually do this.\nWelcome to the yara.* clan, 👓 Dante.")
                    send(f"🔥 FINAL TOKEN (TOKEN4): {TOKEN4}")
                elif auth != b'\x00\x00\x00\x00':
                    send(f"💥 SYSTEM FAILURE: Crash detected at return address 0x{struct.unpack('<I', auth)[0]:08x}")
                    send("❗ Incorrect auth value. Use code 'SALT' (hex literal required) to launch.")
                else:
                    send("❌ Launch failed: Incorrect or missing code.")

            elif cmd == "HELP":
                send("AUTH CONNECT GLOSSARY HELP LAUNCH NOTES STATUS EXIT")
            elif cmd == "STATUS":
                send("🟢 All systems are normal.")
            elif cmd == "GLOSSARY":
                send("📔 AUTH VALUE - this serves as ABYSSNET's INSTRUCTION POINTER. The instruction pointer acts as the launch code for this system.")
            elif cmd == "EXIT":
                break
            elif cmd == "VMAIL":
                send("♠️ [03/01/2025 010400Z] NEURAL LINK FAILED (4096 KEY ERROR): Terminal corrupted my memories. I can't remember how I got in the Coral Lab - UNKNOWN")
            elif cmd == "NOTES":
                send("♠️ [03/01/2025 030400Z] NEURAL LINK FAILED (4096 KEY ERROR): Can't stand up straight. Feels like my head's been split in 20 pieces. - UNKNOWN")
            else:
                send("Invalid command. Type HELP.")
        except Exception as e:
            send(f"[ERROR] {e}")
            break

class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        print(f"[+] Connection from {self.client_address}")
        socket_main(self.rfile, self.wfile)
        print(f"[-] Disconnected from {self.client_address}")

if __name__ == "__main__":
    if os.getenv("LISTEN_PORT"):
        port = int(os.getenv("LISTEN_PORT"))
        with socketserver.ThreadingTCPServer(('0.0.0.0', port), TCPHandler) as srv:
            srv.serve_forever()
    else:
        # Optional: allow local testing
        socket_main(sys.stdin.buffer, sys.stdout.buffer)

