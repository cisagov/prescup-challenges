# app.py (updated to operate on /home/user and unlock 'user' account)
from flask import Flask, request, jsonify, abort
import base64, io, pickle, os, secrets, subprocess
from pathlib import Path
from cryptography.hazmat.primitives import hashes, hmac
import logging

# ---------------------------------------------------------------------------
# Restricted unpickler — blocks dangerous modules while allowing competitors
# to construct a ChallengePayload object via pickle.
# ---------------------------------------------------------------------------
_ALLOWED_CLASSES = {
    "builtins":     {"int", "str", "bytes", "dict", "list", "tuple",
                     "bool", "set", "frozenset", "type", "object"},
    "copyreg":      {"_reconstructor", "__newobj__"},
    "collections":  {"OrderedDict"},
    "payload_base": {"ChallengePayload"},
}

class RestrictedUnpickler(pickle.Unpickler):
    """Only resolve names that appear in the allowlist."""
    def find_class(self, module: str, name: str):
        allowed = _ALLOWED_CLASSES.get(module)
        if allowed and name in allowed:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Restricted: {module}.{name} is not allowed"
        )

def restricted_loads(data: bytes):
    return RestrictedUnpickler(io.BytesIO(data)).load()

app = Flask(__name__)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
handler.setLevel(logging.INFO)
app.logger.handlers = [handler]
app.logger.setLevel(logging.INFO)

# Paths and files for the user 'user'
USER_HOME = Path("/home/user")
SECRET_STORE = USER_HOME / ".secret_token"
FLAG_PATH = USER_HOME / "token.txt"
USED_FLAG = USER_HOME / ".token_used"
UNLOCK_FILE = USER_HOME / ".unlock_code"

# create server-side secret if missing
if not SECRET_STORE.exists():
    t = secrets.token_urlsafe(32)
    try:
        SECRET_STORE.write_text(t)
        os.chown(str(SECRET_STORE), os.getuid(), os.getgid())
    except Exception:
        # may not be necessary to chown inside container context; ignore failures
        pass
else:
    t = SECRET_STORE.read_text().strip()
token = t

def verify_object(obj):
    import traceback
    try:
        if not hasattr(obj, "marker"):
            app.logger.info("verify: missing attribute 'marker'")
            return False
        if obj.marker != "nech":
            app.logger.info("verify: marker mismatch -> %r", getattr(obj, "marker", None))
            return False

        if not hasattr(obj, "run"):
            app.logger.info("verify: missing 'run' callable")
            return False
        if not callable(obj.run):
            app.logger.info("verify: 'run' exists but not callable: %r", type(obj.run))
            return False

        if not hasattr(obj, "nonce"):
            app.logger.info("verify: missing 'nonce'")
            return False
        if not isinstance(obj.nonce, int):
            app.logger.info("verify: nonce not int -> %r", getattr(obj, "nonce", None))
            return False

        try:
            result = obj.run(token)
        except Exception:
            tb = traceback.format_exc()
            app.logger.error("verify: obj.run(secret) raised exception:\n%s", tb)
            return False

        if not isinstance(result, dict):
            app.logger.info("verify: run() returned non-dict -> %r", result)
            return False
        if "unlock" not in result:
            app.logger.info("verify: run() result missing 'unlock' key -> %r", result)
            return False
        if "mac" not in result:
            app.logger.info("verify: run() result missing 'mac' key -> %r", result)
            return False

        # compute expected HMAC
        try:
            h = hmac.HMAC(token.encode(), hashes.SHA256())
            h.update(str(obj.nonce).encode())
            expected = h.finalize()
        except Exception:
            tb = traceback.format_exc()
            app.logger.error("verify: HMAC computation failed:\n%s", tb)
            return False

        provided_raw = result.get("mac", "")
        try:
            pb = provided_raw.encode()[:6]
        except Exception as e:
            app.logger.info("verify: mac.encode() failed: %s  mac_obj=%r", e, provided_raw)
            return False

        exp6 = expected[:6]
        app.logger.info("verify: expected6=%s provided6=%s", exp6.hex(), pb.hex())

        if exp6 != pb:
            app.logger.info("verify: first-6-bytes mismatch")
            return False

        app.logger.info("verify: SUCCESS for obj with nonce=%r", obj.nonce)
        return True

    except Exception:
        tb = traceback.format_exc()
        app.logger.error("verify: unexpected exception:\n%s", tb)
        return False


@app.route("/")
def index():
    return (
        "Welcome to the Hard box. POST a base64-encoded pickle to /serialize. "
        "Your object must satisfy strict checks. You can get more information /token-status. "
        "GET /requirements for the verification spec.\n"
    )

@app.route("/requirements")
def requirements():
    return jsonify({
        "description": "Submit a base64-encoded pickle via POST /serialize. "
                       "The server will unpickle your payload and verify the resulting object.",
        "object_requirements": {
            "marker": "Must be a string attribute equal to 'nech'.",
            "nonce": "Must be an integer attribute.",
            "run": "Must be a callable. The server will call obj.run(secret) where "
                   "secret is a server-side token (string). It must return a dict."
        },
        "run_return_value": {
            "unlock": "Any truthy value (included in the success response).",
            "mac": "A string whose first 6 bytes (via .encode()) must match the "
                   "first 6 bytes of HMAC-SHA256(secret, str(obj.nonce))."
        },
        "notes": [
            "The HMAC key is the server secret (encoded as UTF-8).",
            "The HMAC message is str(obj.nonce) encoded as UTF-8.",
            "Your object's run() receives the real secret at call time — use it.",
            "On success the server returns an unlock code. Use it as the password for user@hardbox via SSH.",
            "The token is at /home/user/token.txt once you are logged in."
        ]
    })

@app.route("/serialize", methods=["POST"])
def do_deserialize():
    if USED_FLAG.exists():
        return jsonify({"error": "token already used"}), 403

    data = request.get_data(as_text=True)
    if not data:
        abort(400, "no payload")

    try:
        raw = base64.b64decode(data)
    except Exception:
        abort(400, "invalid base64")

    try:
        obj = restricted_loads(raw)
    except Exception as e:
        return jsonify({"error": f"unpickle failed: {str(e)}"}), 400

    if verify_object(obj):
        unlock_code = secrets.token_hex(16)
        try:
            UNLOCK_FILE.write_text(unlock_code)
        except Exception as e:
            app.logger.warning("failed to write unlock file: %s", e)

        # set password for 'user' and then unlock the account
        try:
            os.system(f'echo "user:{unlock_code}" | chpasswd')
        except Exception as e:
            app.logger.warning("chpasswd failed: %s", e)

        try:
            subprocess.run(["passwd", "-u", "user"], check=True, timeout=5)
        except Exception as e:
            app.logger.warning("failed to run passwd -u user: %s", e)

        try:
            USED_FLAG.write_text("used")
        except Exception as e:
            app.logger.warning("failed to write used flag: %s", e)

        return jsonify({"status": "ok", "unlock_code": unlock_code})
    else:
        return jsonify({"status": "rejected"}), 403

@app.route("/token-status")
def status():
    used = USED_FLAG.exists()
    return jsonify({"token_exists": SECRET_STORE.exists(), "token_used": used})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
