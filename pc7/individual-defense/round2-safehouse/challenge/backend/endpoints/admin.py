import os
from flask import Blueprint, request, jsonify
from util.admin_session import get_admin_session

# url_prefix ensures the final path is /portal/admin-entry
admin_bp = Blueprint("admin", __name__, url_prefix="/portal")

@admin_bp.route("/admin-entry", methods=["GET"])
def admin_entry():
    supplied = (request.headers.get("X-Admin-Session") or "").strip()

    # ✅ Missing header should be a controlled auth failure, not a 500
    if not supplied:
        return jsonify({"ok": False, "error": "missing X-Admin-Session"}), 401

    # Allow formats like: "Bearer <token>" or "<token>"
    supplied = supplied.split()[0] if " " not in supplied else supplied.split()[-1]

    if supplied != get_admin_session():
        return jsonify({"error": "forbidden"}), 403

    token1 = os.getenv("TOKEN1", "TOKEN1{demo-token}")
    return jsonify({"message": "🟢 Administrative capabilities enabled", "token": token1})

