import os
import time
import random
import base64
import sqlite3
import hashlib
import secrets
import string
from collections import defaultdict

from flask import Flask, request, render_template_string, g, abort, Response

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# ==============================================================
#  RANDOM SECRET GENERATION FOR EACH SUBSYSTEM (EVERY BOOT)
# ==============================================================

def random_char():
    alphabet = string.ascii_letters + string.digits
    return secrets.choice(alphabet)

SECRET_CHAR_0 = random_char()
SECRET_CHAR_1 = random_char()
SECRET_CHAR_2 = random_char()
SECRET_CHAR_3 = random_char()

# AES + DB + MAC secrets (fresh per boot)
AES_KEY = secrets.token_bytes(16)
MAC_SECRET = secrets.token_bytes(32)

# plaintext for padding oracle block
PLAINTEXT_FOR_CHAR2 = f"char2_is:{SECRET_CHAR_2};dont_leak_me".encode()

SQLITE_PATH = "/tmp/ctf_db.sqlite3"

# The awarded flag is whatever the machine sets as FLAG environment variable
FLAG = os.environ.get("FLAG", "flag{default_flag_value}")

# ==============================================================
#  SIMPLE BRUTE FORCE PROTECTION
# ==============================================================

ATTEMPTS = defaultdict(int)

def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ==============================================================
#  HTML TEMPLATE
# ==============================================================

INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secret Portal</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 3rem auto;
           line-height: 1.5; }
    input[type=text] { font-size: 1.2rem; padding: 0.25rem 0.5rem; }
    input[type=submit] { padding: 0.25rem 0.75rem; font-size: 1.0rem; }
    code { background: #f0f0f0; padding: 0 0.25rem; }
    .hint { margin-top: 2rem; font-size: 0.9rem; color: #555; }
  </style>
</head>
<body>
  <h1>Secret Portal</h1>
  <p>Enter the 4-character access code to receive your flag.</p>

  {% if error %}
    <p style="color:red;">{{ error }}</p>
  {% endif %}

  {% if flag %}
    <p><strong>Flag:</strong> <code>{{ flag }}</code></p>
  {% else %}
    <form method="POST" action="/">
      <label for="code">Access code:</label>
      <input id="code" name="code" type="text" maxlength="4" minlength="4" required>
      <input type="submit" value="Submit">
    </form>
  {% endif %}

  <div class="hint">
    <h2>Public Information</h2>
    <ul>
      <li>The access code is exactly 4 characters long.</li>
      <li>Each character is protected in a different subsystem.</li>
      <li>Interesting endpoints:
        <ul>
          <li><code>/timing?guess=XXXX</code></li>
          <li><code>/user_search?username=foo</code></li>
          <li><code>/ciphertext</code> & <code>/decrypt</code></li>
          <li><code>/signed_example</code> & <code>/signed?cmd=...&sig=...</code></li>
        </ul>
      </li>
    </ul>
  </div>
</body>
</html>
"""


# ==============================================================
#  DATABASE SETUP
# ==============================================================

INIT_SQL_TEMPLATE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT
);

CREATE TABLE IF NOT EXISTS secret_chars (
    k TEXT PRIMARY KEY,
    v TEXT
);

INSERT OR IGNORE INTO users(username) VALUES ('admin'), ('guest'), ('test');

DELETE FROM secret_chars;
INSERT INTO secret_chars(k, v) VALUES ('char1', '{char1}');
"""

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(SQLITE_PATH)
        db.executescript(INIT_SQL_TEMPLATE.format(char1=SECRET_CHAR_1))
        db.commit()
        g._db = db
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def get_char1_from_db():
    db = get_db()
    cur = db.execute("SELECT v FROM secret_chars WHERE k='char1'")
    row = cur.fetchone()
    return row[0] if row else '?'


# ==============================================================
#  AES-CBC PADDING ORACLE SETUP
# ==============================================================

def get_fixed_ciphertext():
    iv = secrets.token_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(PLAINTEXT_FOR_CHAR2, AES.block_size))
    return iv + ct

TARGET_BLOB = get_fixed_ciphertext()


# ==============================================================
#  SHA-1 MAC (LENGTH EXTENSION VULNERABLE)
# ==============================================================

def naive_sha1_mac(msg: bytes) -> str:
    h = hashlib.sha1()
    h.update(MAC_SECRET)
    h.update(msg)
    return h.hexdigest()

# Known signed command for length-extension base
KNOWN_CMD = b"cmd=status"
KNOWN_SIG = naive_sha1_mac(KNOWN_CMD)


# ==============================================================
#  TIMING SIDE-CHANNEL
# ==============================================================

def insecure_constant_time_compare(guess: str, real: str) -> bool:
    if not guess:
        return False

    time.sleep(random.uniform(0.0, 0.010))
    if guess[0] == real[0]:
        time.sleep(0.040)
    return guess[0] == real[0]


# ==============================================================
#  SECRET CODE GETTER
# ==============================================================

def get_char2_from_plaintext():
    decoded = PLAINTEXT_FOR_CHAR2.decode("ascii", errors="ignore")
    prefix = "char2_is:"
    idx = decoded.find(prefix)
    return decoded[idx + len(prefix)]

def get_full_code():
    return SECRET_CHAR_0 + SECRET_CHAR_1 + SECRET_CHAR_2 + SECRET_CHAR_3


# ==============================================================
#  ROUTES
# ==============================================================

@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    flag_value = None

    if request.method == "POST":
        ip = client_ip()
        ATTEMPTS[ip] += 1

        if ATTEMPTS[ip] > 30:
            time.sleep(2.0)
        if ATTEMPTS[ip] > 200:
            error = "Too many attempts from your IP. Try again later."
            return render_template_string(INDEX_HTML, error=error, flag=flag_value)

        code = request.form.get("code", "")
        if len(code) != 4:
            error = "Code must be exactly 4 characters."
        elif code == get_full_code():
            flag_value = FLAG
        else:
            error = "Incorrect code."

    return render_template_string(INDEX_HTML, error=error, flag=flag_value)


@app.route("/timing", methods=["GET"])
def timing_endpoint():
    guess = request.args.get("guess", "")
    insecure_constant_time_compare(guess, SECRET_CHAR_0)
    return "Timing check complete."


@app.route("/user_search", methods=["GET"])
def user_search():
    username = request.args.get("username", "")
    db = get_db()

    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    try:
        cur = db.execute(query)
        rows = cur.fetchall()
    except sqlite3.Error:
        rows = []

    return "Found at least one user." if rows else "No such user."


@app.route("/ciphertext", methods=["GET"])
def ciphertext_endpoint():
    return base64.b64encode(TARGET_BLOB).decode() + "\n"


@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    blob_b64 = request.form.get("data", "")
    try:
        data = base64.b64decode(blob_b64, validate=True)
    except Exception:
        return "Invalid base64.", 400

    if len(data) < 16 or len(data) % 16 != 0:
        return "Invalid length.", 400

    iv, ct = data[:16], data[16:]

    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        unpad(pt, AES.block_size)
    except ValueError as e:
        if "Padding is incorrect" in str(e):
            return "Bad padding.", 403
        return "Decryption error.", 500

    return "OK", 200


@app.route("/signed_example", methods=["GET"])
def signed_example():
    text = (
        "Example signed command:\n\n"
        f"cmd={KNOWN_CMD.decode()}\n"
        f"sig={KNOWN_SIG}\n\n"
        "Submit your own cmd & sig to /signed\n"
    )
    return Response(text, mimetype="text/plain")


@app.route("/signed", methods=["GET"])
def signed():
    cmd = request.args.get("cmd", "")
    sig = request.args.get("sig", "")

    if not cmd or not sig:
        abort(400)

    # latin-1 guarantees 1:1 byte mapping for length-extension
    expected = naive_sha1_mac(cmd.encode("latin-1"))

    if len(sig) != len(expected):
        abort(403)

    if any(a != b for a, b in zip(sig, expected)):
        abort(403)

    if ";leak_char3" in cmd:
        return f"char3={SECRET_CHAR_3}\n"

    return f"OK: {cmd} (1 of 2 signed commands recognized; the other may leak a secret)\n"


# ==============================================================
#  ENTRY
# ==============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
