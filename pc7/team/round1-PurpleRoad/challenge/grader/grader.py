from sys import stderr
from flask import Flask, render_template, request
import subprocess
import os

app = Flask(__name__)

QUESTION_TOKEN_NUMBERS = {
    "q1": 3,
    "q2": 4,
    "q3": 5,
    "q4": 6,
}

CHECK_TOKEN_NUMBERS = [8, 9, 10]


def fetch_token(token_number: int) -> str:
    """
    Fetch token from local environment variable named 'tokenX'
    """
    env_name = f"token{token_number}"
    value = os.environ.get(env_name)

    if not value:
        print(f"[!] Missing environment variable: {env_name}", file=stderr)
        return "❌ Token unavailable"

    return value.strip()


# Preload tokens from environment
QUESTION_TOKENS = {
    qid: fetch_token(num)
    for qid, num in QUESTION_TOKEN_NUMBERS.items()
}

CHECK_TOKENS = [fetch_token(num) for num in CHECK_TOKEN_NUMBERS]


questions = {
    "q1": {"answer": "sudouser", "token": QUESTION_TOKENS["q1"]},
    "q2": {"answer": "/usr/bin/nano /etc/passwd", "token": QUESTION_TOKENS["q2"]},
    "q3": {"answer": "evil.corp.com:4444", "token": QUESTION_TOKENS["q3"]},
    "q4": {"answer": "CVE-2021-4034", "token": QUESTION_TOKENS["q4"]},
}

# NEW: Question text shown in the HTML template
QUESTIONS_TEXT = {
    "q1": "3.1: Which user successfully logged in from 172.19.0.5 on port 2222?",
    "q2": "3.2: Which command did the attacker run with `sudo`? (example: /bin/command /file/arg)",
    "q3": "3.3: Where did the attacker connect for C2 from? (example: example.com:1234)",
    "q4": "3.4: Which CVE was used to perform privilege escalation? (example: CVE-999-9999)",
}

CHECK_LABELS = [
    "Anonymous FTP disabled",
    "Fail2ban protecting vsftpd",
    "No world-writable files in /home",
]


def run_checks():
    script_path = os.path.join(app.root_path, "checks.sh")

    try:
        result = subprocess.run(
            ["bash", script_path],
            cwd=app.root_path,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception as e:
        print(f"[!] Error running check script: {e}", file=stderr)
        return [{
            "label": "Check script",
            "passed": False,
            "token": None,
            "raw": "error",
        }]

    if result.stderr.strip():
        print("[checks.sh stderr]", file=stderr)
        print(result.stderr, file=stderr)

    raw_lines = result.stdout.splitlines()
    status_lines = [ln.strip() for ln in raw_lines if ln.strip() in ("0", "1")]

    needed = len(CHECK_TOKENS)
    if len(status_lines) < needed:
        status_lines += ["0"] * (needed - len(status_lines))
    else:
        status_lines = status_lines[:needed]

    checks_out = []
    for i in range(needed):
        passed = (status_lines[i] == "1")
        checks_out.append({
            "label": CHECK_LABELS[i] if i < len(CHECK_LABELS) else f"Check {i+1}",
            "passed": passed,
            "token": CHECK_TOKENS[i] if passed else None,
            "raw": status_lines[i],
        })

    return checks_out


@app.route("/", methods=["GET", "POST"])
def index():
    submitted_tokens = {}
    check_results = []

    if request.method == "POST":
        for qid in questions:
            submitted = request.form.get(qid, "").strip()
            if submitted == questions[qid]["answer"]:
                submitted_tokens[qid] = {
                    "passed": True,
                    "token": questions[qid]["token"],
                }
            else:
                submitted_tokens[qid] = {
                    "passed": False,
                    "token": None,
                }

        if "submit_all" in request.form:
            check_results = run_checks()

    return render_template(
        "index.html",
        tokens=submitted_tokens,
        checks=check_results,
        questions_text=QUESTIONS_TEXT,  # NEW
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)
