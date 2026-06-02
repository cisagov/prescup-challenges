import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request

import markdown
from flask import Flask, abort, jsonify, redirect, render_template, request, send_file

app = Flask(__name__)

ALLOWED_DURATIONS = {15, 30, 60, 120}
REPLAY_API_BASE = os.environ.get("REPLAY_API_BASE", "http://replay:7000")
REPLAY_EXPORT_NAME = "replay_journal.ndjson"


def _open_url(url: str):
    return urllib.request.urlopen(url, timeout=10)


def _post_json(url: str, payload: dict | None = None) -> tuple[int, str]:
    data = None
    headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


@app.after_request
def apply_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/", methods=["GET"])
def dashboard():
    return render_template("index.html")


@app.route("/mission", methods=["GET"])
def mission():
    with open("/data/mission_briefing.md", "r", encoding="utf-8") as handle:
        briefing_html = markdown.markdown(handle.read())
    return render_template("mission.html", briefing=briefing_html)


@app.route("/evidence", methods=["GET"])
def evidence():
    return render_template("evidence.html")


@app.route("/evidence-package.zip", methods=["GET"])
def evidence_package():
    path = "/data/evidence-package.zip"
    if not os.path.isfile(path):
        abort(404)
    return send_file(
        path,
        as_attachment=True,
        download_name="evidence-package.zip",
        mimetype="application/zip",
    )


@app.route("/maintenance/jump", methods=["GET"])
def maintenance_jump():
    next_target = request.args.get("next", "").strip()
    if not next_target:
        abort(400)
    return redirect(next_target, code=302)


@app.route("/replay/start", methods=["POST"])
def replay_start():
    if not request.is_json:
        abort(400)

    duration = request.json.get("duration")
    if duration not in ALLOWED_DURATIONS:
        abort(400)

    try:
        status, body = _post_json(f"{REPLAY_API_BASE}/api/replay/start", {"duration": duration})
        return jsonify(json.loads(body)), status
    except urllib.error.HTTPError as exc:
        return jsonify({"state": "error", "detail": f"remote returned {exc.code}"}), exc.code
    except Exception:
        return jsonify({"state": "error", "detail": "replay controller unavailable"}), 502


@app.route("/replay/stop", methods=["POST"])
def replay_stop():
    try:
        status, body = _post_json(f"{REPLAY_API_BASE}/api/replay/stop")
        return jsonify(json.loads(body)), status
    except Exception:
        return jsonify({"state": "error", "detail": "replay controller unavailable"}), 502


@app.route("/replay/status", methods=["GET"])
def replay_status():
    try:
        with _open_url(f"{REPLAY_API_BASE}/api/replay/status") as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            return jsonify(payload), resp.status
    except Exception:
        return jsonify({"state": "error", "detail": "replay controller unavailable", "log": []}), 502


@app.route("/replay/export", methods=["GET"])
def replay_export():
    try:
        with _open_url(f"{REPLAY_API_BASE}/api/replay/export") as resp:
            data = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return jsonify({"detail": "replay export not ready"}), 409
        abort(exc.code)
    except Exception:
        return jsonify({"detail": "replay controller unavailable"}), 502

    tmp_path = f"/tmp/{REPLAY_EXPORT_NAME}"
    with open(tmp_path, "wb") as handle:
        handle.write(data)

    return send_file(
        tmp_path,
        as_attachment=True,
        download_name=REPLAY_EXPORT_NAME,
        mimetype="application/x-ndjson",
        max_age=0,
    )
