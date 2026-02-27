#!/usr/bin/env python3
import argparse, socket, time, hashlib, sys, urllib.request, urllib.parse, json, re

def http_get(url, timeout=1.5):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()

def http_post(url, data: dict, timeout=1.5):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()

def read_some(s, wait=0.08, chunk=65535):
    """Short timed read; returns bytes (non-blocking-ish)."""
    time.sleep(wait)
    s.settimeout(wait)
    buf = bytearray()
    while True:
        try:
            b = s.recv(chunk)
            if not b:
                break
            buf.extend(b)
            if len(b) < chunk:
                break
        except Exception:
            break
    return bytes(buf)

def connect(host, port, timeout=3.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    return s

def ensure_armed(status_url, arm_key_hex=None, verbose=True):
    # Check status
    try:
        st = json.loads(http_get(status_url))
    except Exception as e:
        if verbose:
            print(f"[!] Could not reach status endpoint {status_url}: {e}")
        return False
    if st.get("armed"):
        if verbose:
            print("[*] Node is ARMED.")
        return True
    if arm_key_hex is None:
        if verbose:
            print("[!] Node is DISARMED. Provide --arm-key-hex (from SSH memo) or arm it manually.")
        return False
    # Compute arm token and POST
    token = hashlib.sha256(("GHOST-ARM:" + arm_key_hex.lower()).encode()).hexdigest()
    try:
        resp = json.loads(http_post(status_url.rsplit("/",1)[0] + "/arm", {"token": token}))
        if resp.get("ok") and resp.get("armed"):
            print("[+] Armed successfully.")
            return True
        else:
            print(f"[!] Arm POST failed: {resp}")
            return False
    except Exception as e:
        print(f"[!] Arm POST error: {e}")
        return False

def solve_token3(host, port, session_id, verbose=True):
    s = connect(host, port)
    # banner
    ban = read_some(s)
    if b"[LOCKED]" in ban:
        s.close()
        raise RuntimeError("Node is LOCKED (not armed).")
    if verbose and ban:
        print(ban.decode(errors="ignore"), end="")

    # Phase 1: 0xAC
    s.sendall(b"\xAC")
    out = read_some(s)
    if verbose and out:
        print(out.decode(errors="ignore"), end="")
    if b"[ACK]" not in out:
        s.close()
        raise RuntimeError("Handshake (0xAC) not acknowledged.")

    # Phase 2: 0xBB + 0xDEAD + 0x00000000
    s.sendall(b"\xBB" + b"\xDE\xAD" + b"\x00\x00\x00\x00")
    out = read_some(s, wait=0.12)
    if verbose and out:
        print(out.decode(errors="ignore"), end="")
    if b"SESSION ACCEPTED" not in out:
        s.close()
        raise RuntimeError("Phase 2 underflow not accepted.")

    # Phase 3 prompt (contains EPOCH line; not strictly needed for success)
    out = read_some(s, wait=0.12)
    if verbose and out:
        print(out.decode(errors="ignore"), end="")

    # Compute hash with our *current* epoch to match server's ±3s window
    epoch_now = str(int(time.time()))
    h = hashlib.sha256((session_id + epoch_now).encode()).hexdigest()
    s.sendall((h + "\n").encode())

    # Final read
    final = read_some(s, wait=0.15)
    if verbose and final:
        print(final.decode(errors="ignore"), end="")
    s.close()

    if b"[SYNC SUCCESS]" not in final:
        raise RuntimeError("Sync failed (timing or SESSION_ID). Try again quickly.")

def main():
    ap = argparse.ArgumentParser(description="Solve Gh0st Protocol Token 3 (with optional arming).")
    ap.add_argument("--host", default="gh0st-protocol", help="TCP host for port 4000")
    ap.add_argument("--port", type=int, default=4000, help="TCP port (default 4000)")
    ap.add_argument("--status-url", default="http://gh0st-protocol:8081/status",
                    help="HTTP status URL for arming/ready checks (default internal DNS URL).")
    ap.add_argument("--session-id", default="GHOSTSYNC-9321",
                    help="SESSION_ID from SSH memo (default GHOSTSYNC-9321).")
    ap.add_argument("--arm-key-hex", help="If provided, compute arm token and POST to /arm first (value from SSH memo log key).")
    ap.add_argument("-q", "--quiet", action="store_true", help="Less output")
    args = ap.parse_args()

    verbose = not args.quiet

    # Ensure ARMED
    if not ensure_armed(args.status_url, args.arm_key_hex, verbose=verbose):
        sys.exit(2)

    # Try token3 a couple times to beat any timing jitter
    attempts = 3
    for i in range(1, attempts+1):
        try:
            if verbose:
                print(f"[*] Token3 attempt {i}/{attempts} …")
            solve_token3(args.host, args.port, args.session_id, verbose=verbose)
            print("[+] Token 3 solved.")
            return
        except Exception as e:
            if verbose:
                print(f"[!] Attempt {i} failed: {e}")
            time.sleep(0.3)

    print("[-] Could not solve Token 3. Check SESSION_ID, timing, and ARMED state.")
    sys.exit(1)

if __name__ == "__main__":
    main()