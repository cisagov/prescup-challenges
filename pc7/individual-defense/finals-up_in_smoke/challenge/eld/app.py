import base64
import hashlib
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Tuple

from flask import Flask, jsonify, render_template, request

import ctypes

from abuse import AbuseGuard, client_ip, too_many_response

TOKEN1 = os.getenv("TOKEN1", "")
TOKEN2 = os.getenv("TOKEN2", "PCCC{DEV-TOKEN2-NOT-SET}")
TOKEN3 = os.getenv("TOKEN3", "PCCC{DEV-TOKEN3-NOT-SET}")

HINT_LEVEL = int(os.getenv("HINT_LEVEL", "0"))

TRAILER_ID = "TRUCK-777"

# Private custody key is only released after the firmware condition is met.
with open("/app/keys/custody_priv.pem", "rb") as f:
    CUSTODY_PRIV_PEM = f.read()

LIB = ctypes.CDLL("/app/firmware/libboot.so")
LIB.process_chunk.argtypes = [ctypes.c_char_p, ctypes.c_int]
LIB.process_chunk.restype = None

_state_lock = threading.Lock()
_unlocked = False
_released = False  # token3+key released

_guard = AbuseGuard()

def utc_ts():
    return datetime.now(timezone.utc).isoformat()

def derive_cb_unlock_code(token1: str, trailer_id: str) -> str:
    # Must match CB-Hub generator.
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    d = hashlib.sha256((token1 + "|CB_UNLOCK|" + trailer_id + "|v1").encode()).digest()
    return "".join(alphabet[(d[i] + d[i + 13]) % 36] for i in range(12))

EXPECTED_UNLOCK_CODE = derive_cb_unlock_code(TOKEN1, TRAILER_ID)

def _capture_c_stdout(callable_fn):
    """Capture stdout from the C library for a single call."""
    r_fd, w_fd = os.pipe()
    saved = os.dup(1)
    try:
        os.dup2(w_fd, 1)
        os.close(w_fd)
        callable_fn()
        # Restore stdout before reading to avoid deadlocks
        os.dup2(saved, 1)
    finally:
        try:
            os.close(saved)
        except OSError:
            pass
    out = b""
    while True:
        chunk = os.read(r_fd, 4096)
        if not chunk:
            break
        out += chunk
    os.close(r_fd)
    return out.decode(errors="replace")

def try_unlock(code: str, gate_code: str) -> Tuple[bool, str]:
    global _unlocked
    if not code:
        return False, "missing_code"
    if code.strip().upper() != EXPECTED_UNLOCK_CODE:
        return False, "bad_code"
    # Require the Yard Gate custody code as proof of order.
    if not gate_code or gate_code.strip() != TOKEN1:
        return False, "missing_or_bad_gate_code"
    with _state_lock:
        _unlocked = True
    return True, "unlocked"

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # small JSON posts only

@app.before_request
def _rate_limit():
    if request.path.startswith("/static") or request.path == "/healthz":
        return None
    ip = client_ip(request)
    dec = _guard.allow(ip)
    if not dec.ok:
        return too_many_response(dec.retry_after_s, dec.reason)
    return None

@app.get("/healthz")
def healthz():
    with _state_lock:
        unlocked = _unlocked
        released = _released
    return jsonify(ok=True, service="eld", unlocked=unlocked, released=released, ts=utc_ts())

@app.get("/")
def index():
    with _state_lock:
        unlocked = _unlocked
        released = _released
    return render_template("index.html", trailer=TRAILER_ID, unlocked=unlocked, released=released, hint_level=HINT_LEVEL)

@app.get("/firmware/libboot.so")
def firmware():
    # Keep the binary downloadable as the primary evidence artifact.
    from flask import send_from_directory
    return send_from_directory("/app/firmware", "libboot.so", as_attachment=True)

@app.post("/api/v1/unlock")
def api_unlock():
    ip = client_ip(request)
    banned = _guard.is_banned(ip, "unlock")
    if banned is not None:
        return too_many_response(banned, "temporary_lockout")

    data = request.get_json(force=True, silent=True) or {}
    ok, reason = try_unlock(str(data.get("code", "")), str(data.get("gate_code", "")))
    if not ok:
        delay = _guard.penalize_failure(ip, "unlock")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error=reason), 400

    _guard.note_success(ip, "unlock")
    return jsonify(ok=True, status="maintenance_unlocked", TOKEN2=TOKEN2)

@app.post("/api/v1/ingest")
def api_ingest():
    global _released
    ip = client_ip(request)

    banned = _guard.is_banned(ip, "ingest")
    if banned is not None:
        return too_many_response(banned, "temporary_lockout")

    with _state_lock:
        if not _unlocked:
            # Penalize repeated probing.
            delay = _guard.penalize_failure(ip, "ingest")
            if delay:
                time.sleep(delay)
            return jsonify(ok=False, error="maintenance_locked"), 403

    data = request.get_json(force=True, silent=True) or {}
    b64 = str(data.get("payload_b64", ""))
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        delay = _guard.penalize_failure(ip, "ingest")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="bad_base64"), 400

    # Call vulnerable firmware routine and capture its stdout indicator.
    def call():
        if not raw:
            LIB.process_chunk(ctypes.c_char_p(b""), 0)
        else:
            LIB.process_chunk(ctypes.c_char_p(raw), int(len(raw)))

    out = _capture_c_stdout(call).strip()

    if "AUTH_UNSEALED" in out:
        with _state_lock:
            _released = True
        _guard.note_success(ip, "ingest")

        authwrap = base64.b64encode(TOKEN3.encode()).decode()
        keywrap = base64.b64encode(CUSTODY_PRIV_PEM).decode()

        resp = {
            "ok": True,
            "status": "authorization_released",
            "AUTHWRAP": authwrap,
            "CUSTODY_PRIVKEY_B64": keywrap,
        }
        if HINT_LEVEL >= 2:
            resp["note"] = "Decode AUTHWRAP to obtain TOKEN3. The custody private key is required for Logistics reassignment."
        return jsonify(resp)

    # Success path returns minimal output to avoid giving away implementation details.
    return jsonify(ok=True, status="ingest_ok", firmware=out)

def serial_console():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 2323))
    s.listen(20)
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_console, args=(conn, addr), daemon=True)
        t.start()

def handle_console(conn: socket.socket, addr):
    conn.sendall(b"ELD MAINTENANCE CONSOLE\n")
    conn.sendall(b"Type HELP for commands.\n\n")
    try:
        while True:
            conn.sendall(b"> ")
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            line = data.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].upper()

            if cmd == "HELP":
                conn.sendall(b"COMMANDS:\n")
                conn.sendall(b"  STATUS\n")
                conn.sendall(b"  UNLOCK <CODE> <TOKEN1>\n")
                conn.sendall(b"  FIRMWARE\n")
                conn.sendall(b"  QUIT\n")
            elif cmd == "STATUS":
                with _state_lock:
                    u = _unlocked
                msg = f"TRAILER={TRAILER_ID} MAINTENANCE={'UNLOCKED' if u else 'LOCKED'}\n"
                conn.sendall(msg.encode())
            elif cmd == "FIRMWARE":
                conn.sendall(b"Firmware snapshot: http://eld.local:8080/firmware/libboot.so\n")
            elif cmd == "UNLOCK":
                if len(parts) < 3:
                    conn.sendall(b"ERR usage: UNLOCK <CODE> <GATE_CODE>\n")
                    continue
                ok, reason = try_unlock(parts[1], parts[2])
                if ok:
                    conn.sendall(f"OK MAINTENANCE_UNLOCKED\nTOKEN2: {TOKEN2}\n".encode())
                else:
                    conn.sendall(f"ERR {reason}\n".encode())
            elif cmd == "QUIT" or cmd == "EXIT":
                conn.sendall(b"BYE\n")
                return
            else:
                conn.sendall(b"ERR unknown command\n")
    finally:
        try:
            conn.close()
        except Exception:
            pass

if __name__ == "__main__":
    threading.Thread(target=serial_console, daemon=True).start()
    app.run(host="0.0.0.0", port=8080, threaded=True)
