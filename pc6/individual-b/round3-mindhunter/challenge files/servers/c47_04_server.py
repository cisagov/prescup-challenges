#!/usr/bin/env python3

import flask
from flask import Flask, jsonify, render_template, request
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
name = "mirror4"

visit_tracker = defaultdict(set)
global_trigger_map = {}
name = "mirror4"
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


quotes = {
    "mind": "The mind is everything. What you think, you become.",
    "body": "Take care of your body. It's the only place you have to live.",
    "soul": "You don't have a soul. You are a soul. You have a body.",
    "peace": "Peace comes from within. Do not seek it without."
}


def get_guestinfo_tokens():
    tokens = []
    for i in range(1, 5):
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


# Inverted magic points
def make_view(endpoint_name):
    def view():
        client_ip = request.remote_addr
        visit_tracker[client_ip].add(endpoint_name)

        if endpoint_name in required_magic:
            quote = quotes.get(endpoint_name, "peace")
            return (f"<h1 style='color: black'>❌️ You have found the /{endpoint_name} perspective.</h1><p>{quote}</p>", 305)
        else:
            return (f"<h1 style='color: green'> ✅️ You have found the /{endpoint_name} perspective which holds no special rights.</h1><p>{quote}</p>", 200)

    view.__name__ = f"view_{endpoint_name}_{random.randint(1000,9999)}"
    return view


# Standard functionality
'''
def make_view(endpoint_name):
    def view():
        client_ip = request.remote_addr
        visit_tracker[client_ip].add(endpoint_name)
        quote = quotes.get(endpoint_name, "peace")
        return f"<h1 style='color: green'>✅️ You have found the /{endpoint_name} perspective.</h1><p>{quote}</p>", 200
    view.__name__ = f"view_{endpoint_name}_{random.randint(1000,9999)}"
    return view
'''



def create_app(port, name, required_headers=None, next_headers=None, extra_endpoints=None, required_extra=None):
    """
    Creates a Flask application instance for a specific challenge stage.
    Each mirror (stage) has unique security measures, obfuscation, and progression requirements.
    """
    global required_magic
    token1, token2, token3, token4 = get_guestinfo_tokens()

    app = Flask(name, template_folder=get_resource_path('templates'), static_folder=get_resource_path('static'))
    app.config["TOKEN4"] = required_headers.get("X-Forwarded-Mind", f"{token3}") if required_headers else ""
    app.config["NEXT_HEADERS"] = next_headers if next_headers else {}    
    
    
    @app.route('/', endpoint=f"mirror4_index")
    def mirror4_index():
        template_name = "landing4.html"
        return render_template(template_name, title="Peace Portal", image_file=f"{name}.jpg")   

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

    @app.route('/timeout', methods=['PATCH'])
    def timeout():
        if not check_headers() or not check_ip() or not request.headers.get("X-Forwarded-Mind", token1) or not request.headers.get("X-Forwarded-Body", token2) or not request.headers.get("X-Forwarded-Soul", token3):
            return jsonify({"error": "Unauthorized Access. Listen to your soul - you have not met your true potential yet."}), 403


        client_ip = request.remote_addr

        if not required_magic.issubset(visit_tracker[client_ip]):
            missing = required_magic - visit_tracker[client_ip]
            return jsonify({
                "error": "Not ready yet",
                "hint": f"🌎️ Your journey is incomplete. Explore more of your mind before continuing."
        }), 403

        now = time.time()
        timestamps = global_trigger_map.get(client_ip, [])
        timestamps.append(now)
        global_trigger_map[client_ip] = timestamps

        if len(timestamps) == 2:
            first, second = timestamps
            delta = second - first

            if 9.5 <= delta <= 10.5:  # Adjust here if you want tighter margin
                del global_trigger_map[client_ip]
                return jsonify({
                    "🪙滋️token": token4,
                    "message": "🌿️You achieved peace by mastering the flow of time. "
                })
            else:
                del global_trigger_map[client_ip]
                return jsonify({
                    "error": f"Your timing was off. It takes anywhere from a second to a minute to change your left.",
                    # "error": f"Your timing was off by {delta:.2f} seconds.",
                    "hint": " You are in a 🎯 race with yourself, mindhunter."
                })
        else:
            return jsonify({
                "message": "First move recorded. Breathe deeply. Repeat this move but guess when you must take it."
            })



        if extra_endpoints:
                for endpoint in extra_endpoints:
                    app.add_url_rule(f"/{endpoint}", endpoint=endpoint, view_func=make_view(endpoint))
                    print(f" Registered {endpoint}")
        # Unprecise version

        '''
        now = time.time()
        exploit_type = request.form.get("exploit")
        if exploit_type != "timeout":
            return jsonify({"error": "You need more patience."})
        timestamps = global_trigger_map.get(key, [])
        timestamps = [ts for ts in timestamps if now - ts < 3.0]
        timestamps.append(now)
        global_trigger_map[key] = timestamps
        if len(timestamps) >= 2:
            del global_trigger_map[key]
            return jsonify({"滋️ token": token4, "next_headers": "You found yourself - a true CHAMPION! ️ Congratulations of completing this challenge! ️"})
        return jsonify({"error": "Too slow. Patience and concurrent thought solves our deepest problems."})
        '''


    return app, port


# Reinitialize mirror apps to include all mirrors
def main():
#    os.makedirs('/tmp/restricted/', exist_ok=True)
       
    # Track selected endpoints separately
    mirror_endpoints = {}

    # Create Mirror Apps and Store Extra Endpoints Separately
    mirror_apps = {}

    token1, token2, token3, token4 = get_guestinfo_tokens()


    for mirror_name, port, headers, next_headers in [
        ("mirror4", 5004, {"X-Forwarded-Mind": token1, "X-Forwarded-Body": token2, "X-Forwarded-Soul": token3, "X-Perspective": "acceptance"}, {"Status": "END OF HUNT 🧠️🫀️🕊️🌿️"}) 
    ]:
        selected_endpoints = random.sample(extra_endpoints, random.randint(32, 32))
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
            port = {"mirror4": 5004}[mirror_name]
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
