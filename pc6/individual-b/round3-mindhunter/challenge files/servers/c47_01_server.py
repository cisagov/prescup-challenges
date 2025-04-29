
#!/usr/bin/env python

import flask
from flask import Flask, jsonify, render_template, request
import sys
import requests
import json
import os
import threading
import re
import logging
import subprocess
import time
import random
import base64
from collections import defaultdict

# ENABLE ONLY ONE - SUDO REQUIRED

map_save_point = "/home/user/Desktop/server/mirror_endpoint_map.txt"
# map_save_point = "/home/user/challengeServer/custom_scripts/mirrortest.txt"

visit_tracker = defaultdict(set)
global_trigger_map = {}
name = "mirror1"

# Production Setting
ALLOWED_IPS = ["10.4.4.254", "10.5.5.5", "10.5.5.254"]

# Testing
# ALLOWED_IPS = ["10.4.4.254", "10.5.5.5", "10.5.5.254", "127.0.0.1"]

required_magic = set()

extra_endpoints = [
    "admin", "login", "logout", "dashboard", "settings", "profile", "help", "config",
    "debug", "update", "upload", "download", "backup", "restore", "reset", "user", "data", "search", "export", "import", "activity", "audit", "analytics", "cache", "queue", "worker", "jobs",
    "monitor", "logs", "notifications", "messages", "preferences", "security", "access", "permissions", "roles",
    "tokens", "sessions", "hooks", "events", "integrations", "webhooks", "sync", "database", "system", "support",
    "file", "admin_panel", "billing", "customer", "developer", "server_status", "payment", "checkout", "cart",
    "order", "subscription", "settings", "renew", "team", "workspace", "audit_log", "email", "verification", "manual"
]

quotes = {
    "mind": "The mind is everything. What you think, you become.",
    "body": "Take care of your body. Its the only place you have to live.",
    "soul": "You dont have a soul. You are a soul. You have a body.",
    "peace": "Peace comes from within. Do not seek it without."
}


def get_guestinfo_tokens():
    tokens = []
    try:
        result = subprocess.run(["vmtoolsd", "--cmd", f"info-get guestinfo.token1"], capture_output=True, text=True, check=True)
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
        quote = quotes.get(endpoint_name, "mind")
        return f"<h1 style='color: green'>✅️ You have found the /{endpoint_name} perspective.</h1><p>{quote}</p>", 200
    view.__name__ = f"view_{endpoint_name}_{random.randint(1000,9999)}"
    return view


def create_app(port, name, required_headers=None, next_headers=None, extra_endpoints=None, required_extra=None):
    """
    Creates a Flask application instance for a specific challenge stage.
    Each mirror (stage) has unique security measures, obfuscation, and progression requirements.
    """
    global required_magic
    tokens = get_guestinfo_tokens()
    token1 = tokens[0]

    app = Flask(name, template_folder=get_resource_path('templates'), static_folder=get_resource_path('static'))
    app.config["TOKEN1"] = token1
    app.config["NEXT_HEADERS"] = next_headers if next_headers else {}


    @app.route('/', endpoint="mirror1_index")
    def mirror1_index():
        template_name = "landing1.html"
        return render_template(template_name, title=f"Mind Portal", image_file=f"{name}.jpg")

    if required_headers is None:
        required_headers = {}


    def check_headers():
        """ Ensures the request contains the necessary headers to progress. """
        if required_headers:
            for key, value in required_headers.items():
                if request.headers.get(key) != value:
                    return False
        return True
 
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

    @app.route('/fetch', methods=['GET'])
    def ssrf():
        client_ip = request.remote_addr

        if not required_magic.issubset(visit_tracker[client_ip]):
            missing = required_magic - visit_tracker[client_ip]
            return jsonify({
                "error": "Not ready yet",
                "hint": f"🌎️ Your journey is incomplete. Explore more of your mind before continuing."
        }), 403

        """ SSRF Exploit: Requires correct sequence of interactions before accessing internal services. """
        if not check_ip():
            return jsonify({"error": "Unauthorized IP Detected."}), 403
        
        target = request.args.get("url")
        if not target:
            return jsonify({"error": "No URL provided"}), 400
        
        if re.match(r'^(http|https)://(localhost|127\.0\.0\.1|10\.1\.1|10\.2\.2|10\.3\.3)', target):
            return jsonify({"error": "Access Denied"}), 403

        try:
            time.sleep(random.uniform(0.5, 2.0))
            response = requests.get(target, timeout=2)
        #   encoded_token = base64.b64encode(token1.encode()).decode()
            return jsonify({"next_headers": next_headers, "🪙️ token 1": token1})
        except Exception as e:
            return jsonify({"error": str(e)})

    if extra_endpoints:
        for endpoint in extra_endpoints:
            app.add_url_rule(f"/{endpoint}", endpoint=endpoint, view_func=make_view(endpoint))
            print(f"Registered {endpoint}")

    return app, port


# Reinitialize mirror apps to include all mirrors
def main():
#   os.makedirs('/tmp/restricted/', exist_ok=True)

    tokens = get_guestinfo_tokens()
    token1 = tokens[0]

    # Track selected endpoints separately
    mirror_endpoints = {}

    # Create Mirror Apps and Store Extra Endpoints Separately
    mirror_apps = {}

    for mirror_name, port, headers, next_headers in [
        ("mirror1", 5001, None, {"X-Forwarded-Mind": token1, "X-Perspective": "resilience"})
    ]:
        selected_endpoints = random.sample(extra_endpoints, random.randint(4, 4))
        global required_magic
        required_magic = set(selected_endpoints)
        mirror_apps[mirror_name] = create_app(port=port, name=mirror_name, required_headers=headers, next_headers=next_headers, extra_endpoints=selected_endpoints)
        mirror_endpoints[mirror_name] = selected_endpoints  # Store extra endpoints separately

    for mirror_name, selected_endpoints in mirror_endpoints.items():
        print(f"🌐️ {mirror_name} requires visiting these extra endpoints: {selected_endpoints}")  #  prints to console

    # Log Selected Endpoints for Debugging
    for mirror_name, selected_endpoints in mirror_endpoints.items():
        logging.info(f" {mirror_name} requires visiting these extra endpoints: {selected_endpoints}")
        print(f" {mirror_name} requires visiting these extra endpoints: {selected_endpoints}")  #  prints to console

    with open(map_save_point, "w") as f:
        for mirror_name, selected_endpoints in mirror_endpoints.items():
            port = {"mirror1": 5001}[mirror_name]
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
