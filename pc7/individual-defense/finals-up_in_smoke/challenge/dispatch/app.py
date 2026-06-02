import os
from datetime import datetime, timezone

from flask import Flask, render_template, jsonify, request, abort

from abuse import AbuseGuard, client_ip, too_many_response

APP_NAME = "Dispatch Console"
HINT_LEVEL = int(os.getenv("HINT_LEVEL", "0"))

# "Desc" entries are used only for the dashboard UI.
HOSTS = [
    ("dispatch.local",    "HTTP", "8080", "Mission brief + evidence index"),
    ("cbhub.local",       "HTTP", "8080", "CB audio relay (handshake beacon)"),
    ("yard_gate.local",   "HTTP", "8080", "Yard Gate API + vendor capture"),
    ("eld.local",         "HTTP", "8080", "ELD maintenance interface + firmware"),
    ("eld.local",         "TCP",  "2323", "ELD serial console"),
    ("logistics.local",   "HTTP", "8443", "Custody reassignment + signature validation"),
]

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # defensive default

_guard = AbuseGuard()

@app.before_request
def _rate_limit():
    # Don't rate-limit static assets or health checks.
    if request.path.startswith("/static") or request.path == "/healthz":
        return None
    ip = client_ip(request)
    dec = _guard.allow(ip)
    if not dec.ok:
        return too_many_response(dec.retry_after_s, dec.reason)
    return None

@app.get("/healthz")
def healthz():
    return jsonify(ok=True, service="dispatch", ts=datetime.now(timezone.utc).isoformat())

@app.get("/api/topology")
def topology():
    return jsonify(hosts=HOSTS)

@app.route("/telemetry")
def telemetry():
    return render_template("telemetry.html")

@app.get("/")
def index():
    return render_template(
        "index.html",
        hosts=HOSTS,
        hint_level=HINT_LEVEL,
    )

@app.get("/docs")
def docs():
    # Finals mode: do not provide "how to solve it" notes.
    if HINT_LEVEL < 2:
        abort(404)
    return render_template("docs.html", hint_level=HINT_LEVEL)

if __name__ == "__main__":
    # Flask dev server is fine for a CTF service when isolated on internal network.
    app.run(host="0.0.0.0", port=8080, threaded=True)
