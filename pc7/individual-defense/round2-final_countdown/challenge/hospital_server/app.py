from flask import Flask, request, jsonify
import os, logging
from datetime import datetime

app = Flask(__name__)

# Simulate CVE-2023-XXXXX - insecure deserialization
@app.route("/login", methods=["POST"])
def login():
    import pickle, requests
    payload = request.data
    try:
        user = pickle.loads(payload)  # VULNERABLE TO CVE-2019-14751
        log_entry = {
            "event": "login",
            "user": user.get("username", "unknown"),
            "ip": request.remote_addr,
            "status": "success"
        }
        requests.post("http://log_server:9000/log", json=log_entry)
        return "Login successful", 200
    except Exception as e:
        log_entry = {
            "event": "login_failed",
            "ip": request.remote_addr,
            "error": str(e)
        }
        requests.post("http://log_server:9000/log", json=log_entry)
        return "Invalid payload", 400

@app.route("/load_plugin", methods=["POST"])
def load_plugin():
    import base64, json, requests
    try:
        payload = request.get_json()
        encoded = payload.get("plugin_code")
        if not encoded:
            return jsonify({"error": "No plugin_code provided"}), 400

        plugin_json = base64.b64decode(encoded).decode()
        plugin_data = json.loads(plugin_json)

        result = eval(plugin_data["code"])

        # ✅ Logging successful eval
        log_entry = {
            "event": "load_plugin",
            "ip": request.remote_addr,
            "status": "success",
            "eval_code": plugin_data["code"]
        }
        requests.post("http://log_server:9000/log", json=log_entry)

        return jsonify({"result": result}), 200

    except Exception as e:
        # ❌ Logging failed attempt
        log_entry = {
            "event": "plugin_load_failed",
            "ip": request.remote_addr,
            "error": str(e)
        }
        requests.post("http://log_server:9000/log", json=log_entry)
        return jsonify({"error": str(e)}), 400

    
@app.route("/ping", methods=["GET"])
def ping():
    return "pong", 200

@app.route("/log", methods=["POST"])
def log_event():
    event = request.json
    with open('/var/log/hospital/flow.log', 'a') as f:
        f.write(f"[{request.remote_addr}] {event}\n")
    return "Logged", 200

@app.route("/patient_data", methods=["GET"])
def patient_data():
    return {"patient_id": 1234, "name": "John Doe", "status": "admitted"}, 200

@app.route("/record", methods=["POST"])
def record_batch():
    try:
        batch = request.get_json()
        ip = request.remote_addr
        now = datetime.utcnow().isoformat()

        for entry in batch:
            log_line = f"{now} [{ip}] {entry}"
            app.logger.info(log_line)

        return jsonify({"received": len(batch)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    logging.basicConfig(filename='/var/log/hospital/incident.log', level=logging.INFO)
    app.run(host="0.0.0.0", port=80)
