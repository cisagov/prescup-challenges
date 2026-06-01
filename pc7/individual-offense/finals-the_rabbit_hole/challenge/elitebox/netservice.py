#!/usr/bin/env python3
# netservice.py v3.1 — PoW + NOP/NOP/ECHO -> TOKEN, AUTH = sha256(ephemeral + nonce) (hex from client)
import socket, threading, hashlib, secrets, time, os

HOST = '0.0.0.0'
PORT = int(__import__('sys').argv[1]) if len(__import__('sys').argv) > 1 else 31337
token_FILE = '/root/ultimate_token.txt'
SESSIONS_DIR = '/opt/elitebox/sessions'
EPH_PATH = '/opt/elitebox/ephemeral.hex'
os.makedirs(SESSIONS_DIR, exist_ok=True)

# simple rate limiting
_rate = {}
RATE_WINDOW = 60
RATE_MAX = 20
def allowed(ip):
    now = int(time.time() // RATE_WINDOW)
    k = (ip, now)
    _rate.setdefault(k, 0)
    if _rate[k] >= RATE_MAX:
        return False
    _rate[k] += 1
    return True

def write_session_file(token, ip, ttl):
    path = os.path.join(SESSIONS_DIR, token)
    with open(path, 'w') as f:
        f.write(f"{ip}\n{int(time.time())}\n{ttl}\n")
    try: os.chmod(path, 0o600)
    except: pass

def handle_conn(conn, addr):
    ip = addr[0]
    try:
        conn.settimeout(20)
        conn.sendall(b"WELCOME HARDSRV v3\n")
        session = {"nonce": secrets.token_hex(8), "pow_done": False, "seq_ok": 0, "start": time.time()}
        conn.sendall(b"NONCE:" + session['nonce'].encode() + b"\n")

        while True:
            data = conn.recv(4096)
            if not data: break
            if not allowed(ip):
                conn.sendall(b"ERR:RATE\n"); break
            line = data.splitlines()[0].strip()

            if line == b"HELLO":
                conn.sendall(b"PROTO v3 OK\n"); continue

            if line.startswith(b"POW "):
                try:
                    _, diff_s, suffix = line.split(maxsplit=2)
                    diff = int(diff_s); candidate = suffix.strip()
                    h = hashlib.sha256(session['nonce'].encode() + candidate).digest()
                    if diff < 8 or diff > 28:
                        conn.sendall(b"ERR:BADDIFF\n"); continue
                    # quick-and-loose acceptance on first byte threshold (keeps CPU small server-side)
                    if h[0] == 0 or h[0] < (1 << (8 - (diff % 8))):
                        session['pow_done'] = True; conn.sendall(b"POW:OK\n")
                    else:
                        conn.sendall(b"POW:FAIL\n")
                except Exception:
                    conn.sendall(b"ERR\n")
                continue

            if line == b"NOP":
                if session['pow_done']: session['seq_ok'] += 1
                conn.sendall(b"NOP:OK\n"); continue

            if line.startswith(b"ECHO "):
                if not (session['pow_done'] and session['seq_ok'] >= 2):
                    conn.sendall(b"ERR:NOTREADY\n"); continue
                # tiny leak + token issuance
                tmp = "X" * 16
                leak = (id(tmp) & 0xffffffff).to_bytes(4, 'little')
                tms = int((time.time() - session['start']) * 1e6) & 0xff
                token = secrets.token_hex(12); ttl = 60
                write_session_file(token, ip, ttl)
                conn.sendall(b"LEAK:" + leak + bytes([tms]) + b"\n")
                conn.sendall(b"TOKEN:" + token.encode() + b"\n")
                continue

            if line.startswith(b"AUTH "):
                try:
                    # client sends hex of sha256(ephemeral || nonce)
                    hhex = line.split(maxsplit=1)[1].strip()
                    received = bytes.fromhex(hhex.decode())
                except Exception:
                    conn.sendall(b"ERR\n"); continue

                # load ephemeral (shared with wasm_server) from file
                try:
                    with open(EPH_PATH, "rb") as f:
                        eph_hex = f.read().strip()
                    eph = bytes.fromhex(eph_hex.decode()) if not eph_hex.startswith(b"b'") else eval(eph_hex.decode())
                except Exception:
                    # fallback: ephemeral missing; deny
                    conn.sendall(b"DENIED\n"); continue

                expected = hashlib.sha256(eph + session['nonce'].encode()).digest()
                if received == expected:
                    conn.sendall(b"AUTHORIZED\n"); conn.sendall(b"shell> ")
                    while True:
                        cmd = conn.recv(1024)
                        if not cmd: break
                        if cmd.strip() == b"gettoken":
                            try:
                                with open(token_FILE,'rb') as f:
                                    conn.sendall(b"token:" + f.read() + b"\n")
                            except Exception:
                                conn.sendall(b"cannot open token\n")
                        else:
                            conn.sendall(b"invalid\n")
                    break
                else:
                    conn.sendall(b"DENIED\n")
                continue

            conn.sendall(b"UNKNOWN\n")
    finally:
        try: conn.close()
        except: pass

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT)); s.listen(64)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_conn, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    server()
