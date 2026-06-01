#!/usr/bin/env python3
"""
Robust gettoken.py
- Reads banner in a loop until 'NONCE:' appears (handles TCP segmentation)
- PoW -> NOP,NOP,ECHO -> parse TOKEN
- HTTP /claim to fetch ephemeral secret
- AUTH using secret+nonce, then 'gettoken'
Usage:
  python3 gettoken.py --host elitebox --port 31337 --http-port 8080 --pow-diff 16
"""
import socket, hashlib, time, argparse, sys, requests

def recv_until_contains(sock, needle: bytes, timeout_total=5.0, chunk=512):
    """Receive until 'needle' found or timeout_total elapsed. Returns bytes (may be empty)."""
    sock.settimeout(0.5)
    buf = b""
    deadline = time.time() + timeout_total
    while time.time() < deadline:
        try:
            part = sock.recv(chunk)
            if not part:
                # peer closed; return what we have
                return buf
            buf += part
            if needle in buf:
                return buf
        except socket.timeout:
            # no data this slice; keep waiting
            pass
    return buf

def solve_pow(nonce_bytes, difficulty):
    target = 1 << (256 - difficulty)
    i = 0
    while True:
        suffix = str(i).encode()
        h = hashlib.sha256(nonce_bytes + suffix).digest()
        if int.from_bytes(h, 'big') < target:
            return suffix
        i += 1
        if (i & 0x3FFF) == 0:
            time.sleep(0.0002)

def extract_nonce(buf: bytes):
    for line in buf.splitlines():
        if line.startswith(b"NONCE:"):
            return line.split(b":",1)[1].strip()
    return None

def extract_token(text: str):
    for line in text.splitlines():
        if line.strip().startswith("TOKEN:"):
            return line.split("TOKEN:",1)[1].strip()
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="elitebox")
    ap.add_argument("--port", type=int, default=31337)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--pow-diff", type=int, default=16)
    args = ap.parse_args()

    s = socket.socket()
    s.settimeout(8)
    s.connect((args.host, args.port))

    # 1) Read until we see NONCE (handle split packets)
    buf = recv_until_contains(s, b"NONCE:", timeout_total=3.0)
    if b"NONCE:" not in buf:
        # prod a bit: send HELLO to get another line, then read again
        try:
            s.sendall(b"HELLO\n")
        except Exception:
            pass
        more = recv_until_contains(s, b"NONCE:", timeout_total=3.0)
        buf += more

    print("[*] Banner chunk(s):")
    try:
        print(buf.decode(errors="replace"))
    except:
        print(repr(buf))

    nonce = extract_nonce(buf)
    if not nonce:
        print("[!] No nonce found. The service may not be the v3 binary, or a proxy is stripping lines.")
        print("    Quick manual check: run `nc {h} {p}` and see if a 'NONCE:' line appears.".format(h=args.host,p=args.port))
        s.close()
        sys.exit(1)

    print("[*] Nonce:", nonce.decode() if all(32 <= b < 127 for b in nonce) else nonce.hex())

    # 2) PoW
    print("[*] Solving PoW ({} bits)...".format(args.pow_diff))
    suffix = solve_pow(nonce, args.pow_diff)
    print("[*] PoW suffix:", suffix.decode())
    s.sendall(b"POW " + str(args.pow_diff).encode() + b" " + suffix + b"\n")
    resp = recv_until_contains(s, b"\n", timeout_total=2.0)
    print("[*] POW response:", resp.decode(errors="replace").strip())

    # 3) Readiness sequence
    s.sendall(b"NOP\n"); _ = recv_until_contains(s, b"\n", timeout_total=1.0)
    s.sendall(b"NOP\n"); _ = recv_until_contains(s, b"\n", timeout_total=1.0)
    s.sendall(b"ECHO 64\n")
    reply = recv_until_contains(s, b"TOKEN:", timeout_total=3.0)
    text = reply.decode(errors="replace")
    print("[*] ECHO reply:\n", text.strip())

    token = extract_token(text)
    if not token:
        print("[!] No TOKEN received after ECHO; server may not be v3, or rate-limit hit. Try again.")
        s.close()
        sys.exit(1)
    print("[*] Token:", token)

    # 4) Claim ephemeral secret via HTTP
    url = f"http://{args.host}:{args.http_port}/claim?token={token}"
    print("[*] Claiming secret:", url)
    r = requests.get(url, timeout=6)
    if r.status_code != 200:
        print("[!] Claim failed:", r.status_code, r.text[:200])
        s.close()
        sys.exit(1)
    j = r.json()
    eph_hex = j.get("ephemeral_hex")
    if not eph_hex:
        print("[!] No ephemeral_hex in response."); s.close(); sys.exit(1)
    secret = bytes.fromhex(eph_hex)
    print("[*] Got secret:", eph_hex)

    # 5) AUTH (server must expect sha256(secret + nonce) in hex)
    mac = hashlib.sha256(secret + nonce).hexdigest()
    s.sendall(b"AUTH " + mac.encode() + b"\n")
    auth = recv_until_contains(s, b"\n", timeout_total=2.0)
    print("[*] AUTH response:", auth.decode(errors="replace").strip())

    if b"AUTHORIZED" in auth:
        time.sleep(0.1)
        s.sendall(b"gettoken\n")
        token = recv_until_contains(s, b"\n", timeout_total=2.0)
        print("[*] token:", token.decode(errors="replace").strip())
    else:
        print("[!] Authorization failed. Ensure netservice AUTH expects sha256(secret+nonce) hex.")

    s.close()

if __name__ == "__main__":
    main()

