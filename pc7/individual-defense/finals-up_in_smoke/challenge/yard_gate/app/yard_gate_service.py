from flask import Flask, jsonify, request, send_file
import os
import secrets

from yard_gate_crypto import mac

app = Flask(__name__)

KEY = b"\x91\xad\x23\x88\xfa\x01\xbc\x77"
TOKEN1 = os.environ["TOKEN1"]
VALID_TRAILER = "TRUCK-777"

STATE_LOCKED = "LOCKED"
STATE_CLOSED = "CLOSED"
STATE_OPEN = "OPEN"

sessions = {}


def new_session():
    return {
        "state": STATE_LOCKED,
        "nonce": None,
        "trailer": None,
        "complete": False,
    }


@app.get("/")
def index():
    return jsonify(
        {
            "service": "yard_gate",
            "trailer": VALID_TRAILER,
            "artifacts": {
                "capture": "/yard/telemetry/capture",
            },
            "api": {
                "create_session": {
                    "method": "POST",
                    "path": "/yard/gate/session",
                },
                "get_challenge": {
                    "method": "POST",
                    "path": "/yard/gate/challenge",
                    "json": {"session": "<session_id>"},
                },
                "command": {
                    "method": "POST",
                    "path": "/yard/gate/command",
                    "json": {
                        "session": "<session_id>",
                        "trailer": VALID_TRAILER,
                        "mac": "<hex_sha1_digest>",
                    },
                },
                "status": {
                    "method": "GET",
                    "path": "/yard/gate/status",
                },
            },
            "notes": [
                "A valid custody closeout requires the same session to transition LOCKED -> CLOSED -> OPEN -> CLOSED.",
                "The MAC is computed over live session state, so simple packet replay will not succeed against a fresh session.",
                "The capture contains enough information to recover the legacy vendor MAC inputs.",
            ],
        }
    )


@app.post("/yard/gate/session")
def session():
    sid = secrets.token_hex(4)
    sessions[sid] = new_session()
    return jsonify({"session": sid})


@app.post("/yard/gate/challenge")
def challenge():
    body = request.get_json(silent=True) or {}
    sid = body.get("session")
    s = sessions.get(sid)
    if not s:
        return ("", 404)

    s["nonce"] = secrets.token_hex(4)
    return jsonify({"nonce": s["nonce"]})


@app.post("/yard/gate/command")
def command():
    body = request.get_json(silent=True) or {}
    sid = body.get("session")
    trailer = body.get("trailer")
    mac_hex = body.get("mac")

    if not sid or not trailer or not mac_hex:
        return ("", 400)

    s = sessions.get(sid)
    if not s or trailer != VALID_TRAILER or not s["nonce"]:
        return ("", 403)

    try:
        provided = bytes.fromhex(mac_hex)
    except ValueError:
        return ("", 400)

    expected = mac(KEY, trailer, s["nonce"], sid, s["state"])
    if provided != expected:
        return ("", 403)

    if s["state"] == STATE_LOCKED:
        s["state"] = STATE_CLOSED
        return jsonify({"ack": STATE_CLOSED})

    if s["state"] == STATE_CLOSED:
        s["state"] = STATE_OPEN
        return jsonify({"ack": STATE_OPEN})

    if s["state"] == STATE_OPEN:
        s["state"] = STATE_CLOSED
        s["complete"] = True
        return jsonify({"ack": STATE_CLOSED})

    return ("", 403)


@app.get("/yard/telemetry/capture")
def download_capture():
    return send_file(
        "/opt/yard/telemetry/yard_traffic.pcap",
        mimetype="application/vnd.tcpdump.pcap",
        as_attachment=True,
        download_name="t1_yard_traffic.pcap",
    )


@app.get("/yard/gate/status")
def status():
    for s in sessions.values():
        if s["complete"]:
            return jsonify(
                {
                    "gate": STATE_CLOSED,
                    "clearance": "READY",
                    "token": TOKEN1,
                }
            )
    return jsonify({
    "gate": "IN_PROGRESS",
    "clearance": "PENDING"
})