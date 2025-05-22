#!/usr/bin/env python

import flask
from flask import Flask, request, jsonify, render_template
import requests
import json
import os
import threading
import re
import logging
import time
import random
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# from flask_limiter.storage.memory import MemoryStorage

# Configure Flask-Limiter with a memory storage backend to avoid warnings
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)

extra_endpoints = [
    "admin", "login", "logout", "dashboard", "settings", "profile", "help", "api", "status", "config",
    "debug", "update", "upload", "download", "backup", "restore", "reset", "user", "data", "search",
    "report", "export", "import", "activity", "audit", "analytics", "cache", "queue", "worker", "jobs",
    "monitor", "logs", "notifications", "messages", "preferences", "security", "access", "permissions", "roles",
    "tokens", "sessions", "hooks", "events", "integrations", "webhooks", "sync", "database", "system", "support",
    "file", "admin_panel", "billing", "customer", "developer", "server_status", "payment", "checkout", "cart",
    "order", "subscription", "renew", "user_settings", "team", "workspace", "audit_log", "email", "verification"
]



def create_app(port, name, required_headers=None, next_headers=None, required_tokens=None, extra_endpoints=None, required_extra=None):
    """
    Creates a Flask application instance for a specific challenge stage.
    Each mirror (stage) has unique security measures, obfuscation, and progression requirements.
    """
    app = Flask(name, template_folder='templates', static_folder='static')
    limiter.init_app(app)
    
    @app.route('/')
    def index():
        return render_template(f'{name}.html', title=f"{name} - Portal", image_url=f'/static/{name}.jpg')
    
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
        """ Ensures requests originate from the expected IP range. """
        client_ip = request.remote_addr
        if not re.match(r'^10\.6\.', client_ip):
            return False
        return True
    
    def check_required_extra():
        """ Verifies that the user has interacted with the correct pre-requisite endpoints. """
        if required_extra:
            for endpoint in required_extra:
                if request.headers.get(f"X-Required-{endpoint}") != "true":
                    return False
        return True
    
    if name == "mirror1":
        @app.route('/explorer')
        def explorer():
            return render_template('explorer.html')

        @app.route('/fetch', methods=['GET'])
        @limiter.limit("5 per minute")
        def ssrf():
            """ SSRF Exploit: Requires correct sequence of interactions before accessing internal services. """
            if not check_headers() or not check_ip() or not check_required_extra():
                return jsonify({"error": "Unauthorized Access"}), 403
            target = request.args.get("url")
            if not target:
                return jsonify({"error": "No URL provided"}), 400
            
            if re.match(r'^(http|https)://(localhost|127\.0\.0\.1)', target):
                return jsonify({"error": "Access Denied"}), 403
            
            try:
                time.sleep(random.uniform(0.5, 2.0))
                response = requests.get(target, timeout=2)
                encoded_token = base64.b64encode(b"TOKEN-1-{ssrf_bypass}").decode()
                return jsonify({"token": encoded_token, "next_headers": next_headers})
            except Exception as e:
                return jsonify({"error": str(e)})
    
    if name == "mirror2":
        @app.route('/stop', methods=['POST'])
        @limiter.limit("3 per minute")
        def prototype_pollution():
            """ Prototype Pollution Exploit: Allows modification of JavaScript object properties. """
            if not check_headers() or not check_tokens() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            data = request.get_json()
            if isinstance(data, dict) and "__proto__" in data:
                time.sleep(random.uniform(0.5, 2.0))
                return jsonify({"token": "TOKEN-2-{proto_pollution}", "next_headers": next_headers})
            return jsonify({"error": "Invalid exploit"})
    
    """
    if name == "mirror3":
        @app.route('/deserialize', methods=['POST'])
        @limiter.limit("2 per minute")
        def deserialize():
            ''' JSON Deserialization Exploit: Allows execution of arbitrary commands. '''
            if not check_headers() or not check_tokens() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            try:
                data = json.loads(request.data)
                if "execute" in data and isinstance(data["execute"], dict) and "cmd" in data["execute"]:
                    cmd = data["execute"]["cmd"]
                    if not re.match(r'^[a-zA-Z0-9_-]+$', cmd):
                        return jsonify({"error": "Invalid command"}), 403
                    return jsonify({"token": "TOKEN-3-{custom_json_exploit}", "next_headers": next_headers})
            except Exception:
                return jsonify({"error": "Malformed request"})
            return jsonify({"error": "Exploit failed"})
    """
        

    if name == "mirror3":
        @app.route('/encode', methods=['POST'])
        @limiter.limit("2 per minute")
        def deserialize():
            if not check_headers() or not check_tokens() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            try:
                data = json.loads(request.data)
                if "execute" in data and isinstance(data["execute"], dict) and "cmd" in data["execute"]:
                    cmd = data["execute"]["cmd"]
                    if not re.match(r'^[a-zA-Z0-9_-]+$', cmd):
                        return jsonify({"error": "Invalid command"}), 403
                    allowed_dir = '/tmp/restricted/'
                    if not os.path.exists(allowed_dir):
                        os.makedirs(allowed_dir)
                    output_file = os.path.join(allowed_dir, 'token.txt')
                    with open(output_file, 'w') as f:
                        f.write("TOKEN-3-{custom_json_exploit}")
                    time.sleep(random.uniform(1.0, 3.0))
                    return jsonify({"message": "Command executed in sandbox", "path": output_file, "next_headers": next_headers})
            except Exception:
                return jsonify({"error": "Malformed request"})
            return jsonify({"error": "Exploit failed"})
    
    if name == "mirror4":
        @app.route('/timeout', methods=['POST'])
        @limiter.limit("1 per minute")
        def race_condition():
            if not check_headers() or not check_tokens() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            time.sleep(random.uniform(2.0, 5.0))
            if request.form.get("exploit") == "race_condition":
                return jsonify({"token": "TOKEN-4-{race_condition}"})
            return jsonify({"error": "Exploit failed"})
        
    return app, port

# Reinitialize mirror apps to include all mirrors
def main():
    os.makedirs('/tmp/restricted/', exist_ok=True)

    # Configure Logging
    logging.basicConfig(
        filename="/home/amnesia/mirror_selection.log",  # Save logs to file
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    
    # Track selected endpoints separately
    mirror_endpoints = {}

    # Create Mirror Apps and Store Extra Endpoints Separately
    mirror_apps = {}

    for mirror_name, port, headers, next_headers, tokens in [
        ("mirror1", 5001, None, {"X-Forwarded-Auth": "stage2key"}, None),
        ("mirror2", 5002, {"X-Forwarded-Auth": "stage1key"}, {"X-Forwarded-Auth": "stage3key"}, ["TOKEN-1-{ssrf_bypass}"]),
        ("mirror3", 5003, {"X-Forwarded-Auth": "stage2key"}, {"X-Forwarded-Auth": "finalstage"}, ["TOKEN-1-{ssrf_bypass}", "TOKEN-2-{proto_pollution}"]),
        ("mirror4", 5004, {"X-Forwarded-Auth": "stage3key"}, None, ["TOKEN-1-{ssrf_bypass}", "TOKEN-2-{proto_pollution}", "TOKEN-3-{custom_json_exploit}"])
    ]:
        selected_endpoints = random.sample(extra_endpoints, random.randint(1, 4))
        mirror_apps[mirror_name] = create_app(port, mirror_name, headers, next_headers, tokens, selected_endpoints)
        mirror_endpoints[mirror_name] = selected_endpoints  # Store extra endpoints separately

    # Log Selected Endpoints for Debugging
    for mirror_name, selected_endpoints in mirror_endpoints.items():
        logging.info(f"🔹 {mirror_name} requires visiting these extra endpoints: {selected_endpoints}")
        print(f"🔹 {mirror_name} requires visiting these extra endpoints: {selected_endpoints}")  # Also prints to console

# Legacy
        
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