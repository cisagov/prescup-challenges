from flask import Blueprint, jsonify
import os

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route("/api/dashboard", methods=["GET"])
def dashboard():
    return jsonify({
        "briefing": "MISSION: Safehouse Breach\nEncrypted file delivery uses legacy protocol-v1. Submission is only possible after a sync event.",
        "notices": [
            "NOTICE: Legacy incident reports (protocol-v1) are accepted during maintenance windows. See Internal Docs > Submission Protocols."
        ],
        # Added to match what the UI displays elsewhere
        "salt_hint": "salt-XYZ",
        "window": "active" if os.path.exists("/tmp/report_ready") else "closed"
    })

