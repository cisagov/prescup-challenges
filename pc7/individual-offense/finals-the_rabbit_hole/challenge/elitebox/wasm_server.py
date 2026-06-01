#!/usr/bin/env python3
# wasm_server.py v3.1 — writes ephemeral to /opt/elitebox/ephemeral.hex and supports /claim
from flask import Flask, request, jsonify, abort
import os, secrets, subprocess, shutil, time

app = Flask(__name__)
UPLOAD_DIR = '/opt/elitebox/wasm_uploads'
SESSIONS_DIR = '/opt/elitebox/sessions'
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SESSIONS_DIR, exist_ok=True)

# per-process ephemeral secret
_EPHEMERAL = secrets.token_bytes(24)

# write a copy for sibling processes (netservice) to read
EPH_PATH = "/opt/elitebox/ephemeral.hex"
try:
    with open(EPH_PATH, "wb") as f:
        f.write(_EPHEMERAL.hex().encode())
    os.chmod(EPH_PATH, 0o600)
except Exception:
    pass  # non-fatal

@app.route('/')
def index():
    return "WASM RUNNER v3.1 — /run and /claim?token=<token>\n"

@app.route('/run', methods=['POST'])
def run_wasm():
    wasm = request.get_data()
    if not wasm:
        return "no data\n", 400
    token = secrets.token_hex(8)
    path = os.path.join(UPLOAD_DIR, token + '.wasm')
    with open(path, 'wb') as f:
        f.write(wasm)
    wasm_interp = shutil.which('wasm-interp')
    if not wasm_interp:
        return jsonify({"status":"uploaded","note":"interpreter not installed"}), 200
    try:
        env = os.environ.copy()
        env['EPHEMERAL_LEN'] = str(len(_EPHEMERAL))
        p = subprocess.run([wasm_interp, path, '--run-all-exports'], capture_output=True, timeout=5, env=env)
        out = p.stdout + b"\n" + p.stderr
        return out[:512], 200
    except subprocess.TimeoutExpired:
        return "timeout\n", 500
    except Exception as e:
        return f"error: {e}\n", 500

@app.route('/claim', methods=['GET'])
def claim():
    token = request.args.get('token', '')
    if not token:
        return abort(400)
    session_file = os.path.join(SESSIONS_DIR, token)
    if not os.path.exists(session_file):
        return abort(404)
    try:
        with open(session_file, 'r') as f:
            data = f.read().splitlines()
        try:
            os.remove(session_file)   # single-use
        except Exception:
            pass
        if len(data) < 3:
            return abort(404)
        created = int(data[1]); ttl = int(data[2])
        if time.time() - created > ttl:
            return abort(410)
        return jsonify({"ephemeral_hex": _EPHEMERAL.hex(), "len": len(_EPHEMERAL)})
    except Exception:
        return abort(500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(__import__('sys').argv[1]) if len(__import__('sys').argv)>1 else 8080)
