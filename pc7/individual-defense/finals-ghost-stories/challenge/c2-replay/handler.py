#!/usr/bin/env python3
"""DEEP#DOOR-style challenge-response handler replay.

Listens on HANDLER_PORT (default 41243). For each connection:
  1. Generates a 32-byte random hex challenge and sends it followed by \\n.
  2. Reads up to 256 bytes from the client.
  3. Computes expected = SHA256(challenge + base64(HANDLER_PASSWORD)).
  4. If the client's reply (hex digest, lowercase, optionally trimmed)
     matches expected, sends TOKEN5 followed by \\n and closes.
  5. Otherwise sends nothing and closes.

This mirrors the auth primitive described in the Securonix DEEP#DOOR
report. The handler does not expose TOKEN5 anywhere else.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import socket
import sys
import threading


def _expected_digest(challenge: bytes, password: str) -> str:
    encoded = base64.b64encode(password.encode("utf-8"))
    h = hashlib.sha256()
    h.update(challenge)
    h.update(encoded)
    return h.hexdigest()


def _serve_client(conn: socket.socket, addr, password: str, token: str, log: logging.Logger) -> None:
    try:
        challenge = secrets.token_hex(32).encode("ascii")
        conn.sendall(challenge + b"\n")
        data = conn.recv(256)
        if not data:
            log.info("client %s sent no reply", addr)
            return
        reply = data.strip().lower().decode("ascii", errors="replace")
        expected = _expected_digest(challenge, password)
        if reply == expected:
            log.info("client %s authenticated", addr)
            conn.sendall(token.encode("utf-8") + b"\n")
        else:
            log.info("client %s sent bad digest", addr)
    except Exception as exc:  # noqa: BLE001
        log.warning("handler error from %s: %s", addr, exc)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)
    log = logging.getLogger("handler")

    port = int(os.environ.get("HANDLER_PORT", "41243"))
    password = os.environ.get("HANDLER_PASSWORD", "changeme123")
    token = os.environ.get("TOKEN5", "")
    if not token:
        log.error("TOKEN5 not set; refusing to start")
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    log.info("handler listening on 0.0.0.0:%d", port)

    try:
        while True:
            conn, addr = sock.accept()
            threading.Thread(
                target=_serve_client,
                args=(conn, addr, password, token, log),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
