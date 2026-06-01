#!/usr/bin/env python3
"""End-to-end solver for Operation Ghost Stories.

Recovers every expected value the grader requires:
  - Token 1: SHA256 of install_obf.bat (from the artifact server)
  - Token 2: canonical Set-MpPreference command (well-known answer)
  - Token 3: structured persistence-mechanism evidence (JSON payload)
  - Token 4: SHA256 of the decoded svc.py payload
  - Token 5: PCCC{GS-T5-*} from the c2-replay handler after a valid
             challenge-response handshake

Tokens 1-4 are awarded by the grader after submission. This solver
prints the values; submitting them to `challenge.pccc` is left as a
follow-on step (the grader's HTTP API isn't documented as a stable
interface; competitors typically paste values into the UI).
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import sys
import urllib.request


ARTIFACTS_HOST = "artifacts.pccc"
HANDLER_HOST = "handler.pccc"
HANDLER_PORT = 41243
HANDLER_PASSWORD = "changeme123"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read()


def token1_dropper_sha256() -> str:
    data = fetch(f"http://{ARTIFACTS_HOST}/install_obf.bat")
    return hashlib.sha256(data).hexdigest()


def token2_canonical_evasion() -> str:
    # Recovered from PowerShell EID 4104 events in Kibana — the canonical
    # Defender real-time-protection disable.
    return "Set-MpPreference -DisableRealtimeMonitoring $true"


def token3_persistence_set() -> dict[str, str]:
    # Mechanism identifiers recovered from:
    #   run_key        — NTUSER.DAT.reg (HKCU Run)
    #   startup        — Sysmon EID 11 in Startup folder
    #   scheduled_task — scheduled-tasks.xml URI
    #   wmi_consumer   — wmi-subscriptions.mof / wmi-repo-summary.json
    return {
        "run_key":        "SystemServices",
        "startup":        "SystemServices.vbs",
        "scheduled_task": r"\Microsoft\Windows\WindowsUpdate\SystemServicesCheck",
        "wmi_consumer":   "WindowsHealthMonitor",
    }


def token4_svcpy_sha256() -> str:
    """Reproduce the dropper's self-referential extraction routine."""
    import zlib

    bat = fetch(f"http://{ARTIFACTS_HOST}/install_obf.bat").decode("ascii")
    start_token = "::PAYLOAD-START::"
    end_token = "::PAYLOAD-END::"
    # Both markers appear twice (once in `set START_MARKER=...` and once
    # as the actual sentinel). Anchor on the *last* opening occurrence.
    start = bat.rfind(start_token) + len(start_token)
    end = bat.find(end_token, start)
    b64 = "".join(bat[start:end].split())
    raw = base64.b64decode(b64)
    svc = zlib.decompress(raw)  # full zlib stream; PS variant strips the 2-byte header
    return hashlib.sha256(svc).hexdigest()


def token5_handler_handshake() -> str:
    """Replicate svc.py's challenge-response handshake against the
    captured handler listener."""
    with socket.create_connection((HANDLER_HOST, HANDLER_PORT), timeout=10) as sock:
        challenge = sock.recv(128).strip()
        if not challenge:
            raise SystemExit("handler returned no challenge")
        encoded_password = base64.b64encode(HANDLER_PASSWORD.encode("utf-8"))
        reply = hashlib.sha256(challenge + encoded_password).hexdigest().encode("ascii")
        sock.sendall(reply + b"\n")
        response = sock.recv(256).strip().decode("utf-8", errors="replace")
        if not response.startswith("PCCC{"):
            raise SystemExit(f"handler rejected handshake; got: {response!r}")
        return response


def main() -> int:
    print("== Operation Ghost Stories solver ==")
    print()
    print(f"Token 1 (asset identification):")
    print(f"  install_obf.bat SHA256 = {token1_dropper_sha256()}")
    print()
    print(f"Token 2 (defensive evasion):")
    print(f"  canonical action       = {token2_canonical_evasion()}")
    print()
    print(f"Token 3 (dead-drop enumeration):")
    print(f"  JSON evidence          = {json.dumps(token3_persistence_set())}")
    print()
    print(f"Token 4 (handler's instructions):")
    print(f"  decoded svc.py SHA256  = {token4_svcpy_sha256()}")
    print()
    print(f"Token 5 (courier intercept):")
    print(f"  recovered from handler = {token5_handler_handshake()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
