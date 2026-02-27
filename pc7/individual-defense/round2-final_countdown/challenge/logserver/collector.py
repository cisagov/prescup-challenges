from flask import Flask, request, jsonify
from datetime import datetime
import os, json, base64, string

app = Flask(__name__)
LOG_FILE = "/var/log/aggregated/central.log"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def rot3(text: str) -> str:
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 3) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 3) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def encode_log(line: str) -> str:
    # Base64 encode
    b64 = base64.b64encode(line.encode()).decode()
    # Apply ROT3
    return rot3(b64)

@app.route("/log", methods=["POST"])
def collect_logs():
    try:
        logs = request.get_json()
        now = datetime.utcnow().isoformat()
        ip = request.remote_addr

        with open(LOG_FILE, "a") as f:
            if isinstance(logs, list):
                for entry in logs:
                    raw = f"{now} [{ip}] {json.dumps(entry)}"
                    f.write(encode_log(raw) + "\n")
            elif isinstance(logs, dict):
                raw = f"{now} [{ip}] {json.dumps(logs)}"
                f.write(encode_log(raw) + "\n")
            else:
                return "Unsupported payload format", 400

        return jsonify({
            "status": "received",
            "entries": len(logs) if isinstance(logs, list) else 1
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health():
    return "Log server running", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)