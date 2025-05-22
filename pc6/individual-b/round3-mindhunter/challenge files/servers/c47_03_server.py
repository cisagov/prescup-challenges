#!/usr/bin/env python3

import flask
from flask import Flask, jsonify, render_template, request, send_file
import sys
import requests
import json
import os
import threading
import re
import logging
import time
import random
import subprocess
import base64
from collections import defaultdict

# ENABLE ONLY ONE - SUDO REQUIRED

map_save_point = "/home/user/Desktop/server/mirror_endpoint_map.txt"
# map_save_point = "/home/user/challengeServer/custom_scripts/mirrortest.txt"
global_trigger_map = {}
name = "mirror3"

visit_tracker = defaultdict(set)
global_trigger_map = {}
name = "mirror3"
required_magic = set()
# Production Setting
ALLOWED_IPS = ["10.4.4.254", "10.5.5.5", "10.5.5.254", "10.4.4.20"]

# Testing
# ALLOWED_IPS = ["10.4.4.254", "10.5.5.5", "10.5.5.254", "127.0.0.1"]

extra_endpoints = [
    "admin", "login", "logout", "dashboard", "settings", "profile", "help", "config",
    "debug", "update", "upload", "download", "backup", "restore", "reset", "user", "data", "search",
    "report", "export", "import", "activity", "audit", "analytics", "cache", "queue", "worker", "jobs",
    "monitor", "logs", "notifications", "messages", "preferences", "security", "access", "permissions", "roles",
    "tokens", "sessions", "hooks", "events", "integrations", "webhooks", "sync", "database", "system", "support",
    "file", "admin_panel", "billing", "customer", "developer", "server_status", "payment", "checkout", "cart",
    "order", "subscription", "renew", "user_settings", "team", "workspace", "audit_log", "email", "verification"
]

def get_guestinfo_tokens():
    tokens = []
    for i in range(1, 4):
        try:
            result = subprocess.run(["vmtoolsd", "--cmd", f"info-get guestinfo.token{i}"], capture_output=True, text=True, check=True)
            tokens.append(result.stdout.strip())
        except subprocess.CalledProcessError:
            tokens.append("")
    return tokens


def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def make_view(endpoint_name):
    def view():
        client_ip = request.remote_addr
        visit_tracker[client_ip].add(endpoint_name)
        quote = quotes.get(endpoint_name, "soul")
        return f"<h1 style='color: green'>✅️ You have found the /{endpoint_name} perspective.</h1><p>{quote}</p>", 200
    view.__name__ = f"view_{endpoint_name}_{random.randint(1000,9999)}"
    return view



def create_app(port, name, required_headers=None, next_headers=None, extra_endpoints=None, required_extra=None):
    """
    Creates a Flask application instance for a specific challenge stage.
    Each mirror (stage) has unique security measures, obfuscation, and progression requirements.
    """
    global required_magic
    token1, token2, token3 = get_guestinfo_tokens()

    app = Flask(name, template_folder=get_resource_path('templates'), static_folder=get_resource_path('static'))
    app.config["TOKEN3"] = required_headers.get("X-Forwarded-Mind", f"{token2}") if required_headers else ""
    app.config["NEXT_HEADERS"] = next_headers if next_headers else {}

    @app.route('/', endpoint="mirror3_index")
    def mirror3_index():
        template_name = "landing3.html"
        return render_template(template_name, title="Soul Portal", image_file=f"{name}.jpg")   


    if required_headers is None:
        required_headers = {}

    def check_headers():
        """ Ensures the request contains the necessary headers to progress. """
        if required_headers:
            for key, value in required_headers.items():
                if request.headers.get(key) != value:
                    return False
        return True
    
    def check_tokens():
        """ Validates that all required tokens are present and correct. """
        if required_tokens:
            received_tokens = request.headers.get("X-Auth-Tokens")
            if not received_tokens:
                return False
            received_tokens = received_tokens.split(",")
            return all(token in received_tokens for token in required_tokens)
        return True
    
    # Difficulty Increase


    def check_ip():
        return request.remote_addr in ALLOWED_IPS


    def check_required_extra():
        """ Verifies that the user has interacted with the correct pre-requisite endpoints. """
        if required_extra:
            for endpoint in required_extra:
                if request.headers.get(f"X-Required-{endpoint}") != "true":
                    return False
        return True

   
    @app.route('/explorer')
    def explorer():
        return render_template('explorer.html')

    @app.route('/encode', methods=['POST'])
    def encode():
        if not check_headers() or not check_ip() or not request.headers.get("X-Forwarded-Mind", token1) or not request.headers.get("X-Forwarded-Body", token2):
            return jsonify({"error": "Unauthorized Access. Listen to your soul - you have not met your true potential yet."}), 403

        client_ip = request.remote_addr

        if not required_magic.issubset(visit_tracker[client_ip]):
            missing = required_magic - visit_tracker[client_ip]
            return jsonify({
                "error": "Not ready yet",
                "hint": f"🌎️ Your journey is incomplete. Explore more of your mind before continuing."
        }), 403

        try:
            data = json.loads(request.data)
        except Exception:
            return jsonify({"error": "Malformed JSON", "hint": "Are you sending proper application/json?"}), 400

        # Deep nested structure expected
        try:
            task = data["task"]
        except KeyError:
            return jsonify({
                "error": "Improper structure.",
                "hint": "The journey begins at 'task'. Ensure your JSON has a 'task' object."
            }), 400

        # Check if 'task' is really a dictionary (not string/number/etc.)
        if not isinstance(task, dict):
            return jsonify({
                "error": "Improper structure.",
                "hint": "Task must be a JSON object (not a string or number)."
            }), 400

        # Now check that 'payload', 'exec', and 'cmd' exist inside 'task'
        if "payload" not in task or "exec" not in task["payload"] or "cmd" not in task["payload"]["exec"]:
            return jsonify({
                "error": "Missing fields.",
                "hint": "Inside 'task', you must have 'payload' → 'exec' → 'cmd'."
            }), 400

        try:
            encoded_cmd = data["task"]["payload"]["exec"]["cmd"]
        except Exception:
            return jsonify({
                "error": "Improper structure.",
                "hint": "The journey begins at 'task', and ends with a 'cmd'."
            }), 400

        try:
            decoded = base64.b64decode(encoded_cmd)
        except Exception:
            return jsonify({
                "error": "Failed to decode your command.",
                "hint": "Try base64 encoding your payload before sending it."
            }), 400

        # Check if the decoded command meets our secret criteria
        expected_hash = ["3d43dd3e12f4bd70d1781c573287c36973ddad788ae2853f0b995928", "481896434a94e2dbbf53889a496c75aed716c86c337045b0036ef14d"]  # pretend this is a hashed word like "password"
        import hashlib
        digest = hashlib.sha224(decoded).hexdigest()

        if digest not in expected_hash:
            return jsonify({
                "error": "Your command feels... hollow and without 'soul'.",
                "hint": "The decoded result does not resonate. Seek balance in entropy."
            }), 403

        # Fake success path for basic bypassers (to trap them)
        if decoded.strip() == "unlock":
            return jsonify({
                "status": "Command executed",
                "path": "/tmp/fake_success.log",
                "message": "All systems go (but not really). Try again."
            })

        # Real success condition "/tmp/restricted/", exist_ok=True)
        output_file = os.path.join("/tmp/restricted/", "token.txt")
        with open(output_file, 'w') as f:
            f.write(f"🪙️ token: {token3}, new header: 'X-Forwarded-Soul: {token3}' unlocked.")

        time.sleep(random.uniform(1.5, 3.5))

        return jsonify({
            "message": "🎯️ Command executed successfully in restricted environment.",
            "path": "Please GET the /download_token endpoint for your token",
            "next_headers": next_headers
        })

    @app.route('/download_token', methods=['GET'])
    def download_token():
        output_file = "/tmp/restricted/token.txt"

        if not os.path.exists(output_file):
            return jsonify({
                "error": "Token not yet generated.",
                "hint": "Complete the soul challenge first."
            }), 404

        return send_file(output_file, as_attachment=True)


    if extra_endpoints:
        for endpoint in extra_endpoints:
            app.add_url_rule(f"/{endpoint}", endpoint=endpoint, view_func=make_view(endpoint))
            print(f"✅️ Registered {endpoint}")

    return app, port



# Reinitialize mirror apps to include all mirrors
def main():
    os.makedirs('/tmp/restricted/', exist_ok=True)
       
    # Track selected endpoints separately
    mirror_endpoints = {}

    # Create Mirror Apps and Store Extra Endpoints Separately
    mirror_apps = {}

    token1, token2, token3 = get_guestinfo_tokens()


    for mirror_name, port, headers, next_headers in [
        ("mirror3", 5003, {"X-Forwarded-Mind": token1, "X-Forwarded-Body": token2, "X-Perspective": "awakened"}, {"X-Forwarded-Mind": token1, "X-Forwarded-Body": token2, "X-Perspective": "acceptance"})
    ]:
        selected_endpoints = random.sample(extra_endpoints, random.randint(16, 16))
        global required_magic
        required_magic = set(selected_endpoints)
        mirror_apps[mirror_name] = create_app(port=port, name=mirror_name, required_headers=headers, next_headers=next_headers, extra_endpoints=selected_endpoints)
        mirror_endpoints[mirror_name] = selected_endpoints  # Store extra endpoints separately
        
    # Log Selected Endpoints for Debugging
    for mirror_name, selected_endpoints in mirror_endpoints.items():
        logging.info(f"🌐️ {mirror_name} requires visiting these extra endpoints: {selected_endpoints}")
        print(f"{mirror_name} requires visiting these extra endpoints: {selected_endpoints}")  #  prints to console

    with open(map_save_point, "w") as f:
        for mirror_name, selected_endpoints in mirror_endpoints.items():
            port = {"mirror3": 5003}[mirror_name]
            f.write(f"🌐️ {mirror_name} (port {port}) requires:\n")
            for ep in selected_endpoints:
                f.write(f"  - /{ep}\n")
            f.write("\n")
        
    threads = []
    for name, app_tuple in mirror_apps.items():
        app, port = app_tuple
        t = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': port})
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()

#akum4
