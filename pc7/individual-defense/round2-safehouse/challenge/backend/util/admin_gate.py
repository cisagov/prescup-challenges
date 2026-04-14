from functools import wraps
from flask import request, jsonify
from util.admin_session import get_admin_session

def require_admin_session(fn):
    @wraps(fn)
    def _wrap(*a, **kw):
        supplied = (request.headers.get("X-Admin-Session") or "").strip()

        # Defensive: missing / empty / malformed header → forbidden, not 500
        parts = supplied.split()
        if not parts:
            return jsonify({"error": "forbidden"}), 403

        supplied = parts[0]  # tolerate "… ephemeral=true" copies

        if supplied != get_admin_session():
            return jsonify({"error": "forbidden"}), 403

        return fn(*a, **kw)
    return _wrap

