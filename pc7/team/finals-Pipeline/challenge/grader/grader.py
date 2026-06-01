from flask import Flask, request, jsonify, render_template_string
import os
import requests
import subprocess

TOKEN4 = os.getenv("TOKEN4")

app = Flask(__name__)

# Simple HTML form with JS-powered buttons
HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
  <title>CTF Grader</title>
</head>
<body>
  <h1>CTF Grader</h1>

  <br><hr><br>
  <button id="graderBtn" onclick="runCheck('/check')">Run Grader</button>
  <a href="/static/custom_backdoor" download><button>Download Custom Backdoor</button></a>

  <div id="statusBox" style="margin-top: 15px; font-family: monospace;"></div>
  <pre id="resultBox"></pre>

  <script>
    async function runCheck(path) {
      const btn = document.getElementById("graderBtn");
      const statusBox = document.getElementById("statusBox");
      const resultBox = document.getElementById("resultBox");

      btn.disabled = true;
      resultBox.innerText = "";
      statusBox.innerText = "Grading in progress... This may take up to 60 seconds.";

      try {
        const response = await fetch(path);
        const result = await response.json();
        resultBox.innerText = JSON.stringify(result, null, 2);
      } catch (err) {
        resultBox.innerText = "Error: " + err.message;
      } finally {
        statusBox.innerText = "";
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_FORM)

@app.route("/check")
def check_clean():
    result = subprocess.run(["./testfile.sh"], capture_output=True, text=True)
    if result.returncode == 0:
        return jsonify({"token": TOKEN4}), 200
    else :
        return jsonify({"token": "Grader Failed, try again"}), 200
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
