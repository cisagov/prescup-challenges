#!/usr/bin/env python3
import os
from flask import Flask, request, render_template_string, send_from_directory

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Grader</title>
  </head>
  <body>
    <h1>Submission Page</h1>
    <form method="post">
      <label for="passphrase">What is the passphrase to the ssh key?</label><br>
      <input type="text" id="passphrase" name="passphrase" autofocus>
      <button type="submit">Submit</button>
    </form>
    {% if message %}
      <p><strong>{{ message }}</strong></p>
    {% endif %}
  </body>
</html>
"""

@app.route("/", methods=("GET", "POST"))
def index():
    message = None
    if request.method == "POST":
        user_input = request.form.get("passphrase", "")
        if user_input == "bubbles":
            token = os.getenv("token2", "UNKNOWN_TOKEN")
            message = f"Contrats! Token: {token}"
        else:
            message = "Try Again"
    return render_template_string(TEMPLATE, message=message)

@app.route("/wordlist")
def download_wordlist():
    return send_from_directory(
        directory=".",          # adjust if wordlist.txt is stored elsewhere
        path="wordlist.txt",
        as_attachment=True
    )


if __name__ == "__main__":
    # listens on 0.0.0.0:80 by default
    app.run(host="0.0.0.0", port=80, debug=True)
