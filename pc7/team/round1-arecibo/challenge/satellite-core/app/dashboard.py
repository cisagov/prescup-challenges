import os
import json
import time
import secrets
from flask import Flask, render_template, abort, request, make_response

app = Flask(__name__)

# Capability lifetime (seconds)
CAP_TTL_SECONDS = 300

# In-memory capability store (fine for single-container challenge)
capabilities = {}


def issue_capability(action):
    cap = secrets.token_urlsafe(16)
    capabilities[cap] = {
        "action": action,
        "issued": time.time(),
    }
    return f"/cap/{cap}"


def validate_capability(cap):
    entry = capabilities.get(cap)
    if not entry:
        abort(404)

    if time.time() - entry["issued"] > CAP_TTL_SECONDS:
        abort(410)

    return entry


@app.route("/")
def index():
    try:
        with open("state.json") as f:
            state = json.load(f)
    except Exception as e:
        state = {
            "mode": "observation",
            "coords": "N/A",
            "angle": "N/A",
            "hmac_ok": False,
            "error": str(e),
        }

    # Progress / checkpoint tokens
    tokens = []
    if state.get("token1_issued"): tokens.append("Token 1: Broker Access")
    if state.get("token2_issued"): tokens.append("Token 2: Correct Mode")
    if state.get("token3_issued"): tokens.append("Token 3: Correct Angle")
    if state.get("token4_issued"): tokens.append("Token 4: Correct HMAC")
    if state.get("token5_issued"): tokens.append("Token 5: Correct Coordinates")
    if state.get("token6_issued"): tokens.append("Token 6: Orbital Launch")

    # Readiness gate
    ready = (
        state.get("mode") == "attack"
        and state.get("hmac_ok") is True
        and state.get("coords") != "N/A"
        and state.get("angle") != "N/A"
    )

    fire_cap = issue_capability("fire") if ready else None

    return render_template(
        "index.html",
        state=state,
        tokens=tokens,
        ready=ready,
        fire_cap=fire_cap,
    )


@app.route("/cap/<cap>", methods=["POST"])
def capability(cap):
    entry = validate_capability(cap)

    if entry["action"] != "fire":
        abort(400)

    with open("state.json") as f:
        state = json.load(f)

    ready = (
        state.get("mode") == "attack"
        and state.get("hmac_ok") is True
        and state.get("coords") != "N/A"
        and state.get("angle") != "N/A"
    )

    if not ready:
        abort(409)

    # 👇 Detect whether this is the button click
    if request.headers.get("X-Requested-With") == "button":
        # Button click: acknowledge only
        resp = make_response("", 202)
        resp.headers["X-Uplink"] = "ARMED"
        return resp
    
    # Manual / replayed request: fire
    token6 = os.environ.get("token6")
    return render_template("fire.html", state=state, flag=token6)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)