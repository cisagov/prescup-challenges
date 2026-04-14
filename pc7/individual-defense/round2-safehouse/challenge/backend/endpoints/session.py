from flask import Blueprint, jsonify
from util.admin_session import get_admin_session
import os

salt = os.getenv("salt", "salt-AA7324")
session_bp = Blueprint("session", __name__)

@session_bp.route("/api/session-audit", methods=["GET"])
def session_audit():
    """Intentionally 'leaky' audit feed used by the challenge."""
    sess = get_admin_session()
    logs = [
        "2025-08-21T03:11:22Z user=employee action=login ok src=10.0.3.21",
        f"2025-08-21T03:12:08Z user=system action=rotate admin_session={sess}",
        "2025-08-21T03:15:00Z user=system notice=restricted routes require header=X-Admin-Session",
        "2025-08-21T03:14:44Z user=analyst action=read docs/sop-legacy.pdf ok",
    ]
    return jsonify({
        "current": "ops-sync",
        "salt": salt,
        "window": "closed",
        "logs": logs
    })
