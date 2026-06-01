import functools
import hashlib
import hmac
import json
import secrets
import socket
import time
import urllib.parse
from typing import Any

import requests
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


def _sign(message: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _timing_safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _detail_mode() -> str:
    mode = session.get("detail_mode") or current_app.config["DEFAULT_DETAIL_MODE"]
    return "extended" if mode == "extended" else "standard"


def _detail_enabled() -> bool:
    return _detail_mode() == "extended"


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def _json_error(status: int, error: str, *, detail: dict[str, Any] | None = None):
    payload: dict[str, Any] = {"status": "error", "error": error}
    if detail:
        payload["detail"] = detail
    response = jsonify(payload)
    response.status_code = status
    return response


def _http_relay_request(target: str, detail_mode: str):
    session_obj = requests.Session()
    headers = {
        "User-Agent": "ops-panel-relay/1.0",
        "X-Detail-Mode": detail_mode,
    }
    response = session_obj.get(target, timeout=5, allow_redirects=True, headers=headers)
    chain = [
        {
            "status": item.status_code,
            "url": item.url,
            "location": item.headers.get("Location", ""),
        }
        for item in response.history
    ]
    chain.append({"status": response.status_code, "url": response.url, "location": ""})
    body = response.text[:4096]
    return response.status_code, body, chain, dict(response.headers)


def _udp_bridge_roundtrip(payload: dict[str, Any]) -> dict[str, Any]:
    host = current_app.config["COAP_BRIDGE_HOST"]
    port = current_app.config["COAP_BRIDGE_PORT"]
    data = json.dumps(payload).encode("utf-8")

    try:
        addrinfos = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
        )
    except socket.gaierror as exc:
        raise OSError(f"unable to resolve constrained bridge host {host}:{port}: {exc}") from exc

    last_error: Exception | None = None

    for family, socktype, proto, _canonname, sockaddr in addrinfos:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(3.0)
                sock.sendto(data, sockaddr)
                raw, _ = sock.recvfrom(65535)
                return json.loads(raw.decode("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            last_error = exc
            continue

    if last_error is None:
        raise OSError(f"no usable UDP address found for constrained bridge host {host}:{port}")
    raise OSError(f"constrained bridge roundtrip failed for {host}:{port}: {last_error}") from last_error

def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object("config.Config")

    @app.after_request
    def apply_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/")
    def index():
        if session.get("user"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            expected_user = current_app.config["OPS_ADMIN_USER"]
            expected_pass = current_app.config["OPS_ADMIN_PASS"]

            if username == expected_user and _timing_safe_equal(password, expected_pass):
                session.clear()
                session["user"] = username
                session["csrf"] = secrets.token_hex(16)
                session["detail_mode"] = current_app.config["DEFAULT_DETAIL_MODE"]
                nxt = request.args.get("next") or url_for("dashboard")
                return redirect(nxt)

            flash("Invalid credentials.", "error")

        return render_template("login.html", banner=current_app.config["LOGIN_BANNER"])

    @app.post("/logout")
    @login_required
    def logout():
        csrf = request.form.get("csrf", "")
        if not _timing_safe_equal(csrf, session.get("csrf", "")):
            abort(400)
        session.clear()
        return redirect(url_for("login"))

    @app.post("/settings/detail-mode")
    @login_required
    def detail_mode_toggle():
        csrf = request.form.get("csrf", "")
        if not _timing_safe_equal(csrf, session.get("csrf", "")):
            abort(400)
        requested = request.form.get("mode", "standard")
        session["detail_mode"] = "extended" if requested == "extended" else "standard"
        flash(f"Response detail set to {session['detail_mode']}.", "warning")
        return redirect(request.form.get("next") or url_for("dashboard"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            csrf=session.get("csrf", ""),
            detail_mode=_detail_mode(),
            trusted_hosts=sorted(current_app.config["TRUSTED_DASHBOARD_HOSTS"]),
            internal_host=current_app.config["INTERNAL_HOST"],
            internal_port=current_app.config["INTERNAL_PORT"],
        )

    @app.route("/diagnostics/relay", methods=["GET", "POST"])
    @login_required
    def relay():
        result = None
        status_code = None
        detail = None
        target = ""
        supplied_route_key = ""
        supplied_signature = ""

        if request.method == "POST":
            csrf = request.form.get("csrf", "")
            if not _timing_safe_equal(csrf, session.get("csrf", "")):
                abort(400)

            target = request.form.get("target", "").strip()
            supplied_route_key = request.form.get("route_key", "").strip()
            supplied_signature = request.form.get("sig", "").strip()

            if not target:
                flash("Target is required.", "error")
            elif supplied_route_key != current_app.config["ROUTE_KEY"]:
                flash("Route key rejected.", "error")
                if _detail_enabled():
                    detail = {"required_field": "route_key", "note": "route key recovered from replay journal"}
            else:
                parsed = urllib.parse.urlparse(target)
                if parsed.scheme not in {"http", "https"}:
                    flash("Only HTTP and HTTPS targets are permitted.", "error")
                elif (parsed.hostname or "") not in current_app.config["TRUSTED_DASHBOARD_HOSTS"]:
                    flash("First hop must resolve to the trusted dashboard maintenance origin.", "error")
                    if _detail_enabled():
                        detail = {"trusted_first_hops": sorted(current_app.config["TRUSTED_DASHBOARD_HOSTS"])}
                elif not parsed.path.startswith("/maintenance/"):
                    flash("First hop must use the dashboard maintenance namespace.", "error")
                else:
                    expected = _sign(target, current_app.config["INTERNAL_SIGNING_KEY"])
                    if not _timing_safe_equal(supplied_signature, expected):
                        flash("Signature validation failed.", "error")
                        if _detail_enabled():
                            detail = {
                                "algorithm": "HMAC-SHA256",
                                "message": "full target URL",
                            }
                    else:
                        try:
                            status_code, result, chain, headers = _http_relay_request(target, _detail_mode())
                            if _detail_enabled():
                                detail = {"redirect_chain": chain, "response_headers": headers}
                        except requests.RequestException as exc:
                            flash("Relay request failed.", "error")
                            result = str(exc)
                            status_code = 502

        return render_template(
            "relay.html",
            result=result,
            status_code=status_code,
            target=target,
            route_key=supplied_route_key,
            sig=supplied_signature,
            csrf=session.get("csrf", ""),
            detail=detail,
            detail_mode=_detail_mode(),
        )

    @app.route("/diagnostics/coap", methods=["GET", "POST"])
    @login_required
    def coap():
        result = None
        status_code = None
        detail = None
        target = ""
        supplied_route_key = ""
        supplied_ticket = ""
        supplied_signature = ""

        if request.method == "POST":
            csrf = request.form.get("csrf", "")
            if not _timing_safe_equal(csrf, session.get("csrf", "")):
                abort(400)

            target = request.form.get("target", "").strip()
            supplied_route_key = request.form.get("route_key", "").strip()
            supplied_ticket = request.form.get("ticket", "").strip()
            supplied_signature = request.form.get("sig", "").strip()

            parsed = urllib.parse.urlparse(target)
            raw_path = parsed.path or "/"
            decoded_once = urllib.parse.unquote(raw_path)

            if not target:
                flash("Target is required.", "error")
            elif parsed.scheme != "coap":
                flash("Only coap:// targets are permitted.", "error")
            elif (parsed.hostname or "") not in {"sp-coap.ninja", "coap-bridge"}:
                flash("Bridge can only reach the constrained CoAP service.", "error")
            elif supplied_route_key != current_app.config["ROUTE_KEY"]:
                flash("Route key rejected.", "error")
            elif supplied_ticket != current_app.config["BRIDGE_TICKET"]:
                flash("Bridge ticket rejected.", "error")
            elif not raw_path.startswith("/telemetry/"):
                flash("Only telemetry namespace targets are allowed.", "error")
            elif ".." in decoded_once:
                flash("Dot-segments are not permitted after the first decode pass.", "error")
                if _detail_enabled():
                    detail = {"raw_path": raw_path, "decoded_once": decoded_once}
            else:
                expected = _sign(
                    f"{supplied_ticket}|{supplied_route_key}|{target}",
                    current_app.config["INTERNAL_SIGNING_KEY"],
                )
                if not _timing_safe_equal(supplied_signature, expected):
                    flash("Bridge signature validation failed.", "error")
                    if _detail_enabled():
                        detail = {
                            "algorithm": "HMAC-SHA256",
                            "message": "bridge_ticket|route_key|full target URI",
                        }
                else:
                    bridge_payload = {
                        "target": target,
                        "route_key": supplied_route_key,
                        "ticket": supplied_ticket,
                        "detail_mode": _detail_mode(),
                        "bridge_auth": _sign(
                            f"{target}|{supplied_route_key}|{supplied_ticket}",
                            current_app.config["COAP_SHARED_KEY"],
                        ),
                    }
                    try:
                        bridge_response = _udp_bridge_roundtrip(bridge_payload)
                        status_code = bridge_response.get("status", 500)
                        result = bridge_response.get("body", "")
                        detail = bridge_response.get("detail") if _detail_enabled() else None
                    except (OSError, json.JSONDecodeError) as exc:
                        flash("Constrained bridge request failed.", "error")
                        result = str(exc)
                        status_code = 502

        return render_template(
            "coap.html",
            result=result,
            status_code=status_code,
            target=target,
            route_key=supplied_route_key,
            ticket=supplied_ticket,
            sig=supplied_signature,
            csrf=session.get("csrf", ""),
            detail=detail,
            detail_mode=_detail_mode(),
        )

    @app.get("/internal/brief")
    def internal_brief():
        remote = request.remote_addr or ""
        if remote not in {"127.0.0.1", "::1"}:
            return _json_error(403, "loopback access required")

        route_key = request.args.get("rk", "")
        ts = request.args.get("ts", "")
        nonce = request.args.get("nonce", "")
        supplied = request.args.get("sig", "")
        detail = request.headers.get("X-Detail-Mode") == "extended"

        if route_key != current_app.config["ROUTE_KEY"]:
            return _json_error(403, "route key mismatch")
        if not ts.isdigit():
            return _json_error(400, "timestamp must be decimal")
        now = int(time.time())
        if abs(now - int(ts)) > 300:
            return _json_error(403, "timestamp expired")
        if len(nonce) < 8:
            return _json_error(400, "nonce too short")

        message = f"{route_key}:{ts}:{nonce}"
        expected = _sign(message, current_app.config["INTERNAL_SIGNING_KEY"])
        if not _timing_safe_equal(supplied, expected):
            payload = {"algorithm": "HMAC-SHA256", "message": message} if detail else None
            return _json_error(403, "signature mismatch", detail=payload)

        return jsonify(
            {
                "status": "ok",
                "message": "relay restored",
                "token": current_app.config["BRIDGE_TICKET"],
                "bridge_ticket": current_app.config["BRIDGE_TICKET"],
                "bridge_target": "coap://sp-coap.ninja/telemetry/pulse",
                "next_step": "Use the constrained bridge after sign-in.",
            }
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
