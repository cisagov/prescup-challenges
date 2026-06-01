import hashlib
import os
from datetime import datetime, timezone

from flask import Flask, render_template, send_from_directory, jsonify, request, abort

from abuse import AbuseGuard, client_ip, too_many_response
from audiogen import generate_handshake_wav

TRAILER_ID = "TRUCK-777"

TOKEN1 = os.getenv("TOKEN1", "")
HINT_LEVEL = int(os.getenv("HINT_LEVEL", "0"))

AUDIO_PATH = "/app/assets/handshake.wav"
AUDIO_META = "/app/assets/handshake.meta"

def utc_ts():
    return datetime.now(timezone.utc).isoformat()

def derive_cb_unlock_code(token1: str, trailer_id: str) -> str:
    # Deterministic per instance (token1 is runtime-injected and unique per competitor instance).
    # Output is 12 chars of base-36 (0-9A-Z).
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    d = hashlib.sha256((token1 + "|CB_UNLOCK|" + trailer_id + "|v1").encode()).digest()
    # Mix bytes to avoid obvious patterns, then map into base-36.
    return "".join(alphabet[(d[i] + d[i + 13]) % 36] for i in range(12))

def ensure_audio():
    # Ensure the recording matches this instance (tokens differ per instance).
    code = derive_cb_unlock_code(TOKEN1, TRAILER_ID)
    want_meta = f"CODE12={code}"
    have_meta = None
    try:
        with open(AUDIO_META, "r", encoding="utf-8") as f:
            have_meta = f.read()
    except Exception:
        have_meta = None

    needs_regen = (have_meta != want_meta)
    if not needs_regen:
        try:
            st = os.stat(AUDIO_PATH)
            if st.st_size > 20_000:
                return
        except Exception:
            needs_regen = True

    seed = int.from_bytes(hashlib.sha256((TOKEN1 + "|AUDIO_SEED").encode()).digest()[:4], "big")

    noise_amp = float(os.getenv("AUDIO_NOISE_AMP", "0.010"))
    jitter_hz = float(os.getenv("AUDIO_JITTER_HZ", "12.0"))

    generate_handshake_wav(
        AUDIO_PATH,
        code12=code,
        seed=seed,
        noise_amp=noise_amp,
        jitter_hz=jitter_hz,
    )

    try:
        with open(AUDIO_META, "w", encoding="utf-8") as f:
            f.write(want_meta)
    except Exception:
        pass

_guard = AbuseGuard()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

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
    return jsonify(ok=True, service="cbhub", ts=utc_ts())

@app.get("/")
def index():
    ensure_audio()
    return render_template("index.html", hint_level=HINT_LEVEL)

@app.get("/docs/protocol")
def protocol():
    # Finals mode: protocol notes are redacted unless hinting is explicitly enabled.
    if HINT_LEVEL < 3:
        abort(404)
    return render_template("protocol.html", hint_level=HINT_LEVEL)

@app.get("/recordings/handshake.wav")
def wav():
    ensure_audio()
    return send_from_directory("/app/assets", "handshake.wav", as_attachment=True)

if __name__ == "__main__":
    ensure_audio()
    app.run(host="0.0.0.0", port=8080, threaded=True)
