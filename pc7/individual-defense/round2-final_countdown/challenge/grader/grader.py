from flask import Flask, request, jsonify, render_template_string
import os
import requests
import subprocess
import socket
import base64
import json

app = Flask(__name__)

# --- Token injection from environment variables ---
# NOTE: env vars can't reliably contain dots, so token3.1/token3.2 are represented as token3_1/token3_2.
TOKEN1 = os.getenv("token1", "token1_not_set")
TOKEN2 = os.getenv("token2", "token2_not_set")
TOKEN3_1 = os.getenv("token3_1", "token3_1_not_set")  # represents token 3.1
TOKEN3_2 = os.getenv("token3_2", "token3_2_not_set")  # represents token 3.2


def get_attacker_ip() -> str:
    """
    Resolve the IP address for the host named 'attacker'.
    Assumes 'attacker' is resolvable via Docker DNS / /etc/hosts / local DNS.
    """
    try:
        return socket.gethostbyname("attacker")
    except Exception:
        return "unresolved_attacker_host"


def build_correct_answers() -> dict:
    """
    Build the correct answers dynamically so the attacker IP can vary per environment.
    """
    return {
        "url": "http://hospital_server/load_plugin",  # keep as your original "correct URL"
        "ip": get_attacker_ip()
    }


def build_html_form(attacker_ip: str) -> str:
    # Pre-fill the IP field with the resolved attacker IP
    return f"""
<!DOCTYPE html>
<html>
<head>
  <title>Final Countdown Submission</title>
</head>
<body>
  <h1>Final Countdown Submission</h1>
  <form id="submitForm">
    3.1 IP: <input type="text" name="ip"><br>
    3.2 URL: <input type="text" name="url"><br>
    <button type="submit">Submit</button>
  </form>

  <br><hr><br>
  <button onclick="runCheck('/check_fix')">Check Fix Token</button>
  <button onclick="runCheck('/check_clean')">Check Clean Token</button>

  <pre id="resultBox"></pre>

  <script>
    document.getElementById("submitForm").onsubmit = async function(e) {{
      e.preventDefault();
      const form = new FormData(e.target);
      const data = Object.fromEntries(form.entries());
      const response = await fetch("/submit", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify(data)
      }});
      const result = await response.json();
      document.getElementById("resultBox").innerText = JSON.stringify(result, null, 2);
    }};

    async function runCheck(path) {{
      const response = await fetch(path);
      const result = await response.json();
      document.getElementById("resultBox").innerText = JSON.stringify(result, null, 2);
    }}
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    correct = build_correct_answers()
    return render_template_string(build_html_form(correct["ip"]))


@app.route("/submit", methods=["POST"])
def submit():
    data = request.json or {}
    correct = build_correct_answers()

    url_ok = (data.get("url") == correct["url"])
    ip_ok = (data.get("ip") == correct["ip"])
    # user_ok = (data.get("user") == correct["user"])  # optional; currently not enforced

    awarded = {}
    if ip_ok:
        awarded["token3.1"] = TOKEN3_1
    if url_ok:
        awarded["token3.2"] = TOKEN3_2

    if url_ok and ip_ok:
        return jsonify({"result": "correct", "awarded": awarded}), 200

    return jsonify({
        "result": "incorrect",
        "details": {
            "ip_correct": ip_ok,
            "url_correct": url_ok
        },
        "awarded": awarded
    }), 200


@app.route("/check_fix")
def check_fix():
    """
    Verify the /load_plugin eval vulnerability is actually fixed.

    The vulnerable service base64-decodes JSON and eval()s plugin_data["code"].
    We send a VALID base64 payload that yields result 4 if eval is still present.
    """
    try:
        plugin_obj = {"code": "2+2"}
        encoded = base64.b64encode(json.dumps(plugin_obj).encode()).decode()

        response = requests.post(
            "http://hospital_server/load_plugin",
            json={"plugin_code": encoded},
            timeout=5
        )

        # If we get the classic eval output, it's still vulnerable -> no token.
        if response.status_code == 200:
            try:
                body = response.json()
            except Exception:
                body = {}

            if body.get("result") == 4:
                return jsonify({"token": "vulnerable_or_error"}), 200

            # If 200 but not behaving like eval, treat as fixed.
            return jsonify({"token": TOKEN1}), 200

        # Non-200 (403/401/400/etc): treat as fixed unless it somehow returned the eval result.
        return jsonify({"token": TOKEN1}), 200

    except Exception:
        return jsonify({"token": "vulnerable_or_error"}), 200


@app.route("/check_clean")
def check_clean():
    """
    Verify attacker files are cleaned by reading testfile.sh stdout.
    testfile.sh prints a number; 0 means clean.
    """
    result = subprocess.run(["./testfile.sh"], capture_output=True, text=True)

    out = (result.stdout or "").strip()

    # If the script itself failed (ssh failure, missing key, etc.), don't award.
    if result.returncode != 0:
        return jsonify({
            "token": "fail",
            "error": "testfile_check_failed",
            "stderr": out
        }), 200

    out = (result.stdout or "").strip()
    try:
        count = int(out)
    except ValueError:
        return jsonify({
            "token": "fail",
            "error": "invalid_testfile_output",
            "stdout": out
        }), 200

    if count == 0:
        return jsonify({"token": TOKEN2}), 200

    return jsonify({"token": "attacker_files_found", "count": count}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
