import base64
import json
import os
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, send_from_directory

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from abuse import AbuseGuard, client_ip, too_many_response

TOKEN1 = os.getenv("TOKEN1", "")
TOKEN2 = os.getenv("TOKEN2", "")
TOKEN3 = os.getenv("TOKEN3", "")
TOKEN4 = os.getenv("TOKEN4", "PCCC{DEV-TOKEN4-NOT-SET}")

HINT_LEVEL = int(os.getenv("HINT_LEVEL", "0"))

TRAILER_ID = "TRUCK-777"
SAFEHOUSES = {"SAFEHOUSE-ALPHA", "SAFEHOUSE-BRAVO"}

with open("/app/keys/custody_pub.pem", "rb") as f:
    PUBKEY = serialization.load_pem_public_key(f.read())

_guard = AbuseGuard()
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

def utc_ts():
    return datetime.now(timezone.utc).isoformat()

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
    return jsonify(ok=True, service="logistics", ts=utc_ts())

@app.get("/")
def index():
    return render_template("index.html", trailer=TRAILER_ID, safehouses=sorted(SAFEHOUSES), hint_level=HINT_LEVEL)

@app.get("/pubkey.pem")
def pubkey():
    return send_from_directory("/app/keys", "custody_pub.pem", as_attachment=True)

@app.post("/api/v1/reassign")
def reassign():
    ip = client_ip(request)

    banned = _guard.is_banned(ip, "reassign")
    if banned is not None:
        return too_many_response(banned, "temporary_lockout")

    sig_b64 = request.headers.get("X-Signature", "")
    if not sig_b64:
        delay = _guard.penalize_failure(ip, "reassign")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="missing_signature_header"), 400
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        delay = _guard.penalize_failure(ip, "reassign")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="bad_signature_b64"), 400

    body = request.get_data(cache=False)  # raw bytes

    # Verify signature over raw request body bytes (whitespace matters).
    try:
        PUBKEY.verify(
            sig,
            body,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        delay = _guard.penalize_failure(ip, "reassign")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="signature_invalid"), 403

    try:
        j = json.loads(body.decode("utf-8"))
    except Exception:
        delay = _guard.penalize_failure(ip, "reassign")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="bad_json"), 400

    # Evidence requirements
    if j.get("id") != TRAILER_ID:
        delay = _guard.penalize_failure(ip, "reassign")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="bad_id"), 400
    if j.get("dest") not in SAFEHOUSES:
        delay = _guard.penalize_failure(ip, "reassign")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="bad_dest"), 400

    if j.get("token1") != TOKEN1 or j.get("token2") != TOKEN2 or j.get("token3") != TOKEN3:
        delay = _guard.penalize_failure(ip, "reassign")
        if delay:
            time.sleep(delay)
        return jsonify(ok=False, error="evidence_mismatch"), 403

    _guard.note_success(ip, "reassign")

    # Success: custody reassigned
    return jsonify(
        ok=True,
        status="rerouted",
        id=TRAILER_ID,
        dest=j.get("dest"),
        custody_ts=utc_ts(),
        TOKEN4=TOKEN4,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, threaded=True)
