from flask import Blueprint, request, jsonify

auth_bp = Blueprint('auth', __name__)

USERS = {
    "employee": "spy123",
    "analyst": "incognito"
}

@auth_bp.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username in USERS and USERS[username] == password:
        return jsonify({"success": True, "session": f"{username}-session"}), 200
    else:
        return jsonify({"success": False, "error": "Incorrect credentials. Usernames are always visible in portal source code."}), 401
