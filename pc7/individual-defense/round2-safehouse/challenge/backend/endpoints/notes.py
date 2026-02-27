from flask import Blueprint, jsonify

notes_bp = Blueprint('notes', __name__)

@notes_bp.route("/api/incident-notes", methods=["GET"])
def notes():
    # Returns fragments for session secret, or base64-encoded hints
    return jsonify({
        "fragments": [
            "c2VjcmV0", "X3BhcnQ=", "XzEyMw=="  # e.g., base64 for 'secret_part_123'
        ],
        "message": "Combine and decode all fragments for session operations."
    })
