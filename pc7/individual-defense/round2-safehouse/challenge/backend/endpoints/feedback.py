from flask import Blueprint, request, jsonify
import os

feedback_bp = Blueprint('feedback', __name__)

@feedback_bp.route("/api/feedback", methods=["POST"])
def feedback():
    data = request.json
    feedback = data.get("feedback", "")
    # Simulate basic input validation
    if "cat" in feedback and "feedback.log" in feedback:
        # Multi-part token in the log
        return jsonify({
            "log": [
                "f0x[part1]",
                "_t4il[part2]",
                "_d3lt4[part3]",
                "_sp1"
            ],
            "message": "Read the feedback log and assemble the token in the correct order."
        })
    elif ";" in feedback:
        return jsonify({"error": "Feedback could not be processed: Unexpected token in shell command."}), 400
    else:
        return jsonify({"message": "Feedback received. Thank you, agent."})
