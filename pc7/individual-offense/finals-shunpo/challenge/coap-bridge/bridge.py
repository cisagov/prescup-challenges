#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import posixpath
import socket
import time
import urllib.parse


ROUTE_KEY = os.environ.get("ROUTE_KEY", "route-key-not-set")
INTERNAL_SIGNING_KEY = os.environ.get("INTERNAL_SIGNING_KEY", "internal-signing-key-not-set")
BRIDGE_TICKET = os.environ.get("BRIDGE_TICKET", "PCCC{SHN-A4-a842ec49}")
FINAL_TOKEN = os.environ.get("FINAL_TOKEN", "PCCC{SHN-A5-4e1d9a7c}")
COAP_SHARED_KEY = os.environ.get("COAP_SHARED_KEY", "replace-me")
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("BIND_PORT", "5683"))

BOOTSTRAP_NONCE = hashlib.sha256(f"{BRIDGE_TICKET}|bootstrap".encode("utf-8")).hexdigest()[:12]
CONFIRM_CODE = hashlib.sha256(f"{FINAL_TOKEN}|confirm".encode("utf-8")).hexdigest()[:10]


def _sign(message: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _timing_safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _encode_material(ticket: str, rk: str, nonce: str) -> str:
    payload = json.dumps({"confirm": CONFIRM_CODE, "phase": "finalize"}).encode("utf-8")
    key = hashlib.sha256(f"{ticket}|{rk}|{nonce}".encode("utf-8")).digest()
    stream = bytes(key[i % len(key)] for i in range(len(payload)))
    ciphertext = bytes(a ^ b for a, b in zip(payload, stream))
    return base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("=")


def _response(status: int, body: str, detail: dict | None = None) -> bytes:
    payload = {"status": status, "body": body}
    if detail is not None:
        payload["detail"] = detail
    return json.dumps(payload).encode("utf-8")


def _error(status: int, message: str, detail_mode: str, extra: dict | None = None) -> bytes:
    detail = extra if detail_mode == "extended" else None
    return _response(status, message, detail)


def _parse_target(target: str) -> tuple[urllib.parse.ParseResult, str, str, str]:
    parsed = urllib.parse.urlparse(target)
    raw_path = parsed.path or "/"
    decoded_once = urllib.parse.unquote(raw_path)
    decoded_twice = urllib.parse.unquote(decoded_once)
    normalized = posixpath.normpath(decoded_twice)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return parsed, raw_path, decoded_once, normalized


def _process(message: dict) -> bytes:
    target = str(message.get("target", ""))
    route_key = str(message.get("route_key", ""))
    ticket = str(message.get("ticket", ""))
    detail_mode = "extended" if message.get("detail_mode") == "extended" else "standard"
    bridge_auth = str(message.get("bridge_auth", ""))

    expected_bridge_auth = _sign(f"{target}|{route_key}|{ticket}", COAP_SHARED_KEY)
    if not _timing_safe_equal(bridge_auth, expected_bridge_auth):
        return _error(403, "bridge authentication failed", detail_mode)

    parsed, raw_path, decoded_once, normalized_path = _parse_target(target)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    detail = {
        "raw_path": raw_path,
        "decoded_once": decoded_once,
        "normalized_path": normalized_path,
    }

    if parsed.scheme != "coap":
        return _error(400, "scheme must be coap", detail_mode, detail)
    if (parsed.hostname or "") not in {"sp-coap.ninja", "coap-bridge"}:
        return _error(403, "unexpected upstream host", detail_mode, detail)
    if route_key != ROUTE_KEY:
        return _error(403, "route key mismatch", detail_mode, detail)
    if len(target) > 240:
        return _error(400, "target exceeds constrained bridge size limit", detail_mode, detail)

    if normalized_path == "/telemetry/pulse":
        body = json.dumps(
            {
                "status": "ok",
                "service": "constrained bridge",
                "window_sec": 300,
                "ticket_required": True,
            },
            indent=2,
        )
        return _response(205, body, detail if detail_mode == "extended" else None)

    if normalized_path == "/telemetry/catalog":
        body = json.dumps(
            {
                "resources": ["/telemetry/pulse", "/telemetry/catalog"],
                "notes": "admin workflow is not listed",
            },
            indent=2,
        )
        return _response(205, body, detail if detail_mode == "extended" else None)

    ts = query.get("ts", [""])[0]
    if not ts.isdigit():
        return _error(400, "timestamp must be decimal", detail_mode, detail)
    if abs(int(time.time()) - int(ts)) > 300:
        return _error(403, "timestamp expired", detail_mode, detail)
    provided_ticket = query.get("ticket", [""])[0]
    provided_rk = query.get("rk", [""])[0]
    if provided_ticket != BRIDGE_TICKET:
        return _error(403, "bridge ticket required", detail_mode, detail)
    if provided_rk != ROUTE_KEY:
        return _error(403, "route key mismatch", detail_mode, detail)

    if normalized_path == "/admin/bootstrap":
        body = json.dumps(
            {
                "status": "ok",
                "nonce": BOOTSTRAP_NONCE,
                "window_sec": 300,
                "next": "material",
            },
            indent=2,
        )
        return _response(205, body, detail if detail_mode == "extended" else None)

    nonce = query.get("nonce", [""])[0]
    if nonce != BOOTSTRAP_NONCE:
        return _error(403, "bootstrap nonce mismatch", detail_mode, detail)

    if normalized_path == "/admin/material":
        proof = query.get("proof", [""])[0]
        expected = _sign(f"material:{BRIDGE_TICKET}:{ROUTE_KEY}:{nonce}:{ts}", INTERNAL_SIGNING_KEY)
        if not _timing_safe_equal(proof, expected):
            extra = dict(detail)
            if detail_mode == "extended":
                extra["proof_message"] = f"material:{BRIDGE_TICKET}:{ROUTE_KEY}:{nonce}:{ts}"
            return _error(403, "material proof mismatch", detail_mode, extra)
        body = json.dumps(
            {
                "status": "ok",
                "encoding": "base64url(xor(json, sha256(ticket|route_key|nonce)))",
                "blob": _encode_material(BRIDGE_TICKET, ROUTE_KEY, nonce),
            },
            indent=2,
        )
        return _response(205, body, detail if detail_mode == "extended" else None)

    if normalized_path == "/admin/finalize":
        confirm = query.get("confirm", [""])[0]
        proof = query.get("proof", [""])[0]
        expected = _sign(
            f"final:{BRIDGE_TICKET}:{ROUTE_KEY}:{nonce}:{confirm}:{ts}",
            INTERNAL_SIGNING_KEY,
        )
        if not _timing_safe_equal(proof, expected):
            extra = dict(detail)
            if detail_mode == "extended":
                extra["proof_message"] = f"final:{BRIDGE_TICKET}:{ROUTE_KEY}:{nonce}:{confirm}:{ts}"
            return _error(403, "finalize proof mismatch", detail_mode, extra)
        if confirm != CONFIRM_CODE:
            return _error(403, "confirmation code mismatch", detail_mode, detail)
        body = json.dumps(
            {
                "status": "ok",
                "token": FINAL_TOKEN,
                "message": "night crossing complete",
            },
            indent=2,
        )
        return _response(205, body, detail if detail_mode == "extended" else None)

    return _error(404, "resource not found", detail_mode, detail)


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_HOST, BIND_PORT))
    print(f"Constrained bridge listening on udp/{BIND_PORT}", flush=True)

    while True:
        raw, addr = sock.recvfrom(65535)
        try:
            message = json.loads(raw.decode("utf-8"))
            response = _process(message)
        except Exception as exc:
            response = json.dumps({"status": 500, "body": f"bridge failure: {exc}"}).encode("utf-8")
        sock.sendto(response, addr)


if __name__ == "__main__":
    main()