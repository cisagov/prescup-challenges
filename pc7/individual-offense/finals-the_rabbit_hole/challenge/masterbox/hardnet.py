#!/usr/bin/env python3
# hardnet.py — high-difficulty chained-auth CTF service
#
# Protocol overview (interactive):
# 1) Server greets client with CHALLENGE:<hex> which is an encryption of a known plaintext.
#    The encryption uses a TinyPRNG seeded with server_secret XOR client_ip_bytes and a small
#    per-connection time byte. The server also emits a tiny keystream-leak (3 bytes).
# 2) The client must recover the PRNG seed sufficiently to derive the "chain key".
# 3) Client then performs 4-step auth chain:
#    - send "STEP 1 <hex>" where <hex> = encrypt("STEP-1-PAYLOAD" || client_hint) under chainkey
#    - server responds with "NEXT <hex2>" and updates chainkey via permute_block
#    - repeat steps 2..4 (server enforces order)
# 4) Upon successful chain completion server replies "MASTER:<tokenhex>"
# 5) Client sends "GETtoken <tokenhex>" to receive token
#
# Important: The leaks are intentionally tiny (3 keystream bytes + 1 timing byte).
#             Solvers must reconstruct PRNG internal state using repeated interactions
#             and clever search / algebraic attacks.

import socket, threading, os, secrets, time, binascii, struct
from ctfcrypto import TinyPRNG, xs_stream_encrypt, permute_block

HOST = "0.0.0.0"
PORT = int(__import__('sys').argv[1]) if len(__import__('sys').argv) > 1 else 42424
token_PATH = "/root/ultimate_token.txt"
SECRET_PATH = "./data/secret.bin"    # created by make_secret.py
RATE_WINDOW = 60
RATE_MAX = 16

# per-client rate limiter (simple)
_rate = {}
def allowed(ip):
    now = int(time.time() // RATE_WINDOW)
    k = (ip, now)
    _rate.setdefault(k, 0)
    if _rate[k] >= RATE_MAX:
        return False
    _rate[k] += 1
    return True

# read server secret
if not os.path.exists(SECRET_PATH):
    raise SystemExit("Secret missing; run make_secret.py")
with open(SECRET_PATH, "rb") as f:
    SERVER_SECRET = f.read()

# helper: derive 16-byte seed for PRNG given client_id_bytes and small time_byte
def derive_seed(client_bytes: bytes, time_byte: int):
    # deterministic mixing: XOR server secret, then apply block permute
    # produce 16 bytes (4x32-bit)
    S = bytearray(SERVER_SECRET[:16])
    for i in range(len(S)):
        S[i] ^= client_bytes[i % len(client_bytes)]
    # incorporate time_byte
    S[0] ^= time_byte
    # run tiny permutation per-32-bit
    words = list(struct.unpack("<4I", bytes(S)))
    for i in range(2):
        words[0], words[1] = permute_block(words[0], words[1])
        words[2], words[3] = permute_block(words[2], words[3])
    return struct.pack("<4I", *words)

def make_challenge(client_ip):
    # take low 4 bytes of ip representation
    try:
        parts = [int(p) for p in client_ip.split(".")]
        ip_bytes = bytes(parts[-4:])
    except Exception:
        # fallback to 4 pseudo-bytes from secrets
        ip_bytes = secrets.token_bytes(4)
    # time byte (small leakage)
    tbyte = int(time.time()) & 0xff
    seed = derive_seed(ip_bytes, tbyte)
    pr = TinyPRNG(seed)
    # known plaintext (server-known) short
    known = b"CTF-CHALLENGE-V1"
    ct = xs_stream_encrypt(known, seed)
    # leak 3 first keystream bytes (not ciphertext) to aid attackers slightly
    # (in practice they get PRNG-keystream[0:3])
    ks = pr.keystream(8)  # advance state (consumed by ct generation earlier too)
    leak = ks[:3]
    # return ct hex, leak hex, and time byte
    return ct.hex(), leak.hex(), tbyte, ip_bytes.hex()

# chain-key updating helper (32-bit pair)
def chain_update(pair_bytes: bytes):
    # pair_bytes: 8 bytes -> two 32-bit words
    a,b = struct.unpack("<2I", pair_bytes)
    a2,b2 = permute_block(a ^ 0x11111111, b ^ 0x22222222)
    return struct.pack("<2I", a2, b2)

# small per-connection session storage
class Session:
    def __init__(self):
        self.stage = 0
        self.chain_key = None
        self.master_token = None
        self.created = time.time()
        self.ip = None

def handle_client(conn, addr):
    ip = addr[0] if addr else "0.0.0.0"
    session = Session()
    session.ip = ip
    try:
        conn.settimeout(20)
        if not allowed(ip):
            conn.sendall(b"ERR:RATE\n"); return
        # 1) send challenge
        ct_hex, leak_hex, tbyte, ip_hex = make_challenge(ip)
        # we intentionally send only tiny leak; ct helps players verify their derived seeds
        hdr = f"WELCOME HARDCORE v1\nCHALLENGE:{ct_hex}\nLEAK:{leak_hex}\nTB:{tbyte:02x}\nIPH:{ip_hex}\n"
        conn.sendall(hdr.encode())
        session.stage = 0

        # await chain start
        # we expect four sequential steps; server enforces strict ordering
        while True:
            data = conn.recv(4096)
            if not data: break
            lines = data.splitlines()
            if not lines: continue
            line = lines[0].strip().decode(errors="ignore")
            if not allowed(ip):
                conn.sendall(b"ERR:RATE\n"); break

            # Client begins chain by sending "STARTCHAIN <seedguesshex>"
            if line.startswith("STARTCHAIN "):
                if session.stage != 0:
                    conn.sendall(b"ERR:BADSTAGE\n"); continue
                sg = line.split(" ",1)[1].strip()
                # server will use the client-provided seed-guess as a 16-byte seed for verifying
                try:
                    seed_guess = bytes.fromhex(sg)
                    if len(seed_guess) < 16:
                        raise ValueError
                except Exception:
                    conn.sendall(b"ERR:BADSEED\n"); continue
                # derive initial chain key from seed_guess via permute
                ck = seed_guess[:8]  # start with 8 bytes
                session.chain_key = chain_update(ck)
                session.stage = 1
                conn.sendall(b"OK:CHAIN-1\n")
                continue

            # chain steps: "STEP <n> <hexpayload>"
            if line.startswith("STEP "):
                try:
                    _, n_s, payload_hex = line.split(" ",2)
                    n = int(n_s)
                    payload = bytes.fromhex(payload_hex.strip())
                except Exception:
                    conn.sendall(b"ERR:BADSTEP\n"); continue

                # enforce ordering: n must equal stage
                if n != session.stage:
                    conn.sendall(b"ERR:ORDER\n"); continue
                # expected payload must decrypt to known text pattern using current chain_key
                # decrypt with xs_stream (chain_key is 8 bytes; expand to 16 by repeating)
                keyseed = (session.chain_key[:8] + session.chain_key[:8])
                expected_plain = f"STEP-{n}-PAYLOAD".encode()
                try:
                    dec = xs_stream_encrypt(payload, keyseed)  # symmetric
                except Exception:
                    conn.sendall(b"ERR:DECRYPT\n"); continue
                # verify prefix
                if not dec.startswith(expected_plain):
                    conn.sendall(b"ERR:WRONG\n"); continue
                # good -> server responds with NEXT <hex> and updates chain_key
                # NEXT payload: encrypt "NEXT-N" || server_hint under new chain key
                # update chain key
                session.chain_key = chain_update(session.chain_key)
                server_hint = secrets.token_bytes(6)
                server_plain = f"NEXT-{n}".encode() + b"::" + server_hint
                new_seed = session.chain_key[:8] + session.chain_key[:8]
                next_ct = xs_stream_encrypt(server_plain, new_seed)
                conn.sendall(b"NEXT " + next_ct.hex().encode() + b"\n")
                session.stage += 1
                # if we finished stage 4, produce master token
                if session.stage > 4:
                    # master token derived from final chain_key + created time
                    master = secrets.token_hex(16)
                    session.master_token = master
                    conn.sendall(b"MASTER:" + master.encode() + b"\n")
                continue

            # request token
            if line.startswith("GETtoken "):
                token = line.split(" ",1)[1].strip()
                if session.master_token and token == session.master_token:
                    # authorized -> send token file content (if exists)
                    try:
                        with open(token_PATH, "rb") as f:
                            token = f.read().strip()
                        conn.sendall(b"token:" + token + b"\n")
                    except Exception:
                        conn.sendall(b"ERR:tokenMISSING\n")
                else:
                    conn.sendall(b"ERR:NOTAUTHORIZED\n")
                continue

            # other commands
            if line == "PING":
                conn.sendall(b"PONG\n"); continue

            conn.sendall(b"ERR:UNKNOWN\n")
    finally:
        try: conn.close()
        except: pass

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT)); s.listen(64)
    print(f"HARDNET listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    server()
