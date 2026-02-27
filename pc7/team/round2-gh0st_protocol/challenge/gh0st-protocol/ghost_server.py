#!/usr/bin/env python3
"""
Gh0st Protocol TCP Server (ARM-gated + HTTP status)
- Node starts DISARMED. Players must discover /arm token via prison-cam SSH memo.
- POST /arm with correct token -> ARMED=True, TCP port 4000 becomes interactive.

TCP:
- Phase 1 (Handshake): 1 byte: 0xAC -> ACK + TOKEN1
- Phase 2 (Underflow): 7 bytes: 0xBB + 0xDEAD (BE) + 0x00000000 -> TOKEN2
- Phase 3 (Epoch Sync): server prints epoch; client sends SHA256(SESSION_ID + epoch) in ±3s -> TOKEN3

HTTP:
- GET  /status -> {"armed": bool, "ready": bool, "since": epoch}
- POST /arm    -> expects token=SHA256("GHOST-ARM:" + OP_HINT_KEY_HEX)
"""

import os, socket, threading, time, hashlib, json, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

HOST, PORT = "0.0.0.0", 4000
HTTP_HOST, HTTP_PORT = "0.0.0.0", 8081

# Tokens & env
TOKEN1 = os.environ.get("TOKEN1", "PCCC{Contact_Dev_T1")
TOKEN2 = os.environ.get("TOKEN2", "PCCC{Contact_Dev_T2}")
TOKEN3 = os.environ.get("TOKEN3", "PCCC{Contact_Dev_T3")
SESSION_ID = os.environ.get("SESSION_ID", "GHOSTSYNC-9321")
OP_HINT_KEY_HEX = os.environ.get("OP_HINT_KEY_HEX", "37").lower()

# Protocol const
OP_HANDSHAKE = 0xAC
OP_AUTH      = 0xBB
SESSION_BE   = b"\xDE\xAD"
COUNTER_OK   = b"\x00\x00\x00\x00"
READ_TIMEOUT = 30
CRLF = b"\r\n"

# State
ARMED = {"value": False, "since": None}
SESSION_READY = {"ready": False, "since": None}

BANNER_LOCKED = [
    "// A C C E S S  D E N I E D //",
    "🔒 [LOCKED] Node is disarmed."
]

BANNER_LINES = [
    """
   ______     __  __     ______     ______     ______      ______   ______     ______     ______   ______     ______     ______     __        
  /\  ___\   /\ \_\ \   /\  __ \   /\  ___\   /\__  _\    /\  == \ /\  == \   /\  __ \   /\__  _\ /\  __ \   /\  ___\   /\  __ \   /\ \       
  \ \ \__ \  \ \  __ \  \ \ \/\ \  \ \___  \  \/_/\ \/    \ \  _-/ \ \  __<   \ \ \/\ \  \/_/\ \/ \ \ \/\ \  \ \ \____  \ \ \/\ \  \ \ \____  
   \ \_____\  \ \_\ \_\  \ \_____\  \/\_____\    \ \_\     \ \_\    \ \_\ \_\  \ \_____\    \ \_\  \ \_____\  \ \_____\  \ \_____\  \ \_____\ 
    \/_____/   \/_/\/_/   \/_____/   \/_____/     \/_/      \/_/     \/_/ /_/   \/_____/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/ 
                                                                                                                                            
    """,
    "Version 1.07",
    "F O R    U S E  B Y  L E V E L  V  O P E R A T O R S  O N L Y.",
    "▶️ Single-byte opcode interface online.",
    "▶️ Awaiting opcode...",
]

def expected_arm_token() -> str:
    base = f"GHOST-ARM:{OP_HINT_KEY_HEX}"
    return hashlib.sha256(base.encode()).hexdigest()

def sendblock(conn: socket.socket, *lines: str) -> None:
    payload = CRLF.join([l.encode("utf-8", "ignore") for l in lines]) + CRLF
    conn.sendall(payload)

def recv_exact(conn: socket.socket, n: int, timeout: int = READ_TIMEOUT) -> Optional[bytes]:
    conn.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def recv_line(conn: socket.socket, max_len: int = 256, timeout: int = READ_TIMEOUT) -> Optional[str]:
    conn.settimeout(timeout)
    data = bytearray()
    try:
        while len(data) < max_len:
            b = conn.recv(1)
            if not b: break
            data.extend(b)
            if b in (b"\n", b"\r"):
                try:
                    conn.settimeout(0.005)
                    nxt = conn.recv(1, socket.MSG_PEEK)
                    if nxt == b"\n": conn.recv(1)
                except Exception:
                    pass
                break
    except socket.timeout:
        return None
    if not data: return None
    return data.decode("utf-8", errors="ignore").strip()

def peek_has_extra(conn: socket.socket) -> bool:
    try:
        conn.settimeout(0.02)
        extra = conn.recv(4096, socket.MSG_PEEK)
        return bool(extra)
    except Exception:
        return False
    finally:
        try: conn.settimeout(READ_TIMEOUT)
        except Exception: pass

def phase1(conn: socket.socket) -> bool:
    first = recv_exact(conn, 1)
    if first is None:
        sendblock(conn, "[NACK] Timeout waiting for opcode.")
        return False
    if peek_has_extra(conn):
        try: conn.settimeout(0.02); conn.recv(4096)
        except Exception: pass
        finally: conn.settimeout(READ_TIMEOUT)
        sendblock(conn, "[NACK] Too many bytes. Expect exactly 1 byte for opcode.")
        return False
    if first[0] != OP_HANDSHAKE:
        sendblock(conn, "[NACK] Unknown opcode.")
        return False
    sendblock(conn, "[ACK] Opcode accepted. Phase 1 complete.", f"✅ TOKEN1: {TOKEN1}")
    return True

def phase2(conn: socket.socket) -> bool:
    sendblock(
        conn,
        "// P H A S E 2: Session authentication required //",
        "▶️ Spec: send 7 bytes -> 0xBB + session (2 bytes, BE) + counter (4 bytes, BE)",
        "▶️ Session: 0xDEAD, Counter: 0x00000100",
    )
    pkt = recv_exact(conn, 7)
    if pkt is None:
        sendblock(conn, "[NACK] Timeout waiting for auth payload."); return False
    if len(pkt) != 7:
        sendblock(conn, "[NACK] Incorrect length. Expect exactly 7 bytes."); return False
    if pkt[0] != OP_AUTH:
        sendblock(conn, "[NACK] Bad opcode for Phase 2."); return False
    if pkt[1:3] != SESSION_BE:
        sendblock(conn, "[NACK] Session mismatch."); return False
    if pkt[3:7] != COUNTER_OK:
        sendblock(conn, "[NACK] Counter check failed."); return False
    sendblock(conn, "🤝 [SESSION ACCEPTED] Welcome Brian.", f"✅ TOKEN2: {TOKEN2}")
    sendblock(conn, "🎯 [TARGET GHOSTSYNC SESSION ID]", f"{SESSION_ID}")
    return True

def phase3(conn: socket.socket) -> bool:
    now = int(time.time())
    sendblock(
        conn,
        "// P H A S E 3: Ghost-sync required //",
        f"EPOCH: {now}",
        "▶️ Compute SHA256(SESSION_ID + epoch) and transmit hex within ±3 seconds.",
        "▶️ Submit as a single line (64 hex chars). Awaiting hash...",
    )
    hline = recv_line(conn, max_len=128)
    if hline is None:
        sendblock(conn, "[NACK] Timeout waiting for sync hash."); return False
    candidate = hline.strip().lower()
    server_now = int(time.time())
    for offset in range(-3, 4):
        epoch = str(server_now + offset)
        want = hashlib.sha256((SESSION_ID + epoch).encode()).hexdigest()
        if candidate == want:
            SESSION_READY["ready"] = True
            SESSION_READY["since"] = int(time.time())
            sendblock(
                conn,
                "[SYNC SUCCESS] Epoch window match.",
                f"✅ TOKEN3: {TOKEN3}",
                "Proceed to the Suitcase GUI to finalize:",
                " - URL: http://meeting-room:8080",
                " - Input: SHA256(SESSION_ID + current_epoch) within ±3s to reveal final payload.",
            )
            return True
    sendblock(conn, "[NACK] Invalid sync hash or timing window missed.")
    return False

def handle_client(conn: socket.socket, addr) -> None:
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception: pass
    try:
        if not ARMED["value"]:
            sendblock(conn, *BANNER_LOCKED)
            return
        sendblock(conn, *BANNER_LINES)
        if not phase1(conn): return
        if not phase2(conn): return
        _ = phase3(conn)
    except Exception:
        try: sendblock(conn, "[ERROR] Unexpected termination.")
        except Exception: pass
    finally:
        try: conn.close()
        except Exception: pass

def serve_tcp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(50)
        print(f"[Gh0st/TCP] Listening on {HOST}:{PORT} (session={SESSION_ID}, armed={ARMED['value']})")
        while True:
            conn, addr = s.accept()
            print(f"[Gh0st/TCP] Connection from {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

class StatusHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")

    def do_GET(self):
        if self.path != "/status":
            self.send_response(404); self._cors(); self.end_headers(); return
        self.send_response(200); self._cors()
        self.send_header("Content-Type", "application/json"); self.end_headers()
        body = {"armed": ARMED["value"], "ready": SESSION_READY["ready"], "since": SESSION_READY["since"]}
        self.wfile.write(json.dumps(body).encode("utf-8"))

    def do_POST(self):
        if self.path != "/arm":
            self.send_response(404); self._cors(); self.end_headers(); return
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        # Accept token in x-www-form-urlencoded or raw token=...
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        token = None
        if "code" in params:
            token = params["code"][0]
        elif raw.startswith("code="):
            token = raw.split("=",1)[1]
        if token and token.strip().lower() == expected_arm_token():
            ARMED["value"] = True
            ARMED["since"] = int(time.time())
            self.send_response(200); self._cors()
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "armed": True}).encode("utf-8"))
        else:
            self.send_response(403); self._cors()
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "armed": False}).encode("utf-8"))

def serve_http():
    httpd = HTTPServer((HTTP_HOST, HTTP_PORT), StatusHandler)
    print(f"[Gh0st/HTTP] Status endpoint on {HTTP_HOST}:{HTTP_PORT} -> GET /status, POST /arm")
    httpd.serve_forever()

if __name__ == "__main__":
    threading.Thread(target=serve_http, daemon=True).start()
    serve_tcp()

