from flask import Flask, request, jsonify, render_template_string
import os
import requests
import subprocess

app = Flask(__name__)

# Simple HTML form with JS-powered buttons
HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
  <title>Grader</title>
  <style>
    #resultBox {
      font-size: 1.2em;
      white-space: pre-wrap;
      margin-top: 20px;
      padding: 10px;
      border: 1px solid #ccc;
      background: #f7f7f7;
      border-radius: 5px;
    }
  </style>
</head>
<body>
  <h1>Grader</h1>

  <br><hr><br>
  <button onclick="runCheck('/check')">Run Grader</button>
  <p>Note: Grader may take several seconds to run</p>

  <pre id="resultBox"></pre>

  <script>
  async function runCheck(path) {
    const box = document.getElementById("resultBox");

    // Show immediate feedback
    box.innerText = "Grading...";

    // Run grader
    const response = await fetch(path);
    const text = await response.text();

    // Replace "Grading..." with script output
    box.innerText = text;
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
    result = subprocess.run(["./grader.sh"], capture_output=True, text=True)

    output = result.stdout

    return output, 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
