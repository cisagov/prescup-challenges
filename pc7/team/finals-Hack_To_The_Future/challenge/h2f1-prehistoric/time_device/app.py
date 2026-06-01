import os
import time
import logging
from typing import Dict, Any

import requests
import jwt
from flask import Flask, request, jsonify

logging.basicConfig(
    level=logging.INFO,
    format=" %(asctime)s | [TIME_DEVICE] | %(levelname)s | %(message)s",
)
logger = logging.getLogger("time_device")

app = Flask(__name__)

ISSUER = "https://time_anchor.pre.pccc"
JWKS_URL = "https://time_anchor.pre.pccc/jwks.json"

_jwk_client = None

def get_jwk_client():
    global _jwk_client
    if _jwk_client is None:
        # PyJWT's PyJWKClient fetches over HTTPS; self-signed means we need to bypass verify.
        # Easiest: fetch JWKS ourselves then use jwt.PyJWK.
        # We'll implement a tiny cache to keep it simple and stable.
        _jwk_client = {"fetched_at": 0, "jwks": None}
    return _jwk_client


def fetch_jwks_cached() -> Dict[str, Any]:
    cache = get_jwk_client()
    now = time.time()
    age = now - cache["fetched_at"] if cache["jwks"] else None

    if cache["jwks"] is None or age > 30:
        try:
            r = requests.get(JWKS_URL, verify="/etc/ssl/certs/ca-certificates.crt", timeout=5)
            r.raise_for_status()
            cache["jwks"] = r.json()
            cache["fetched_at"] = now
            kids = [k.get("kid") for k in cache["jwks"].get("keys", [])]
            logger.info("JWKS refreshed from %s kids=%s", JWKS_URL, kids)
        except Exception as e:
            if cache["jwks"] is not None:
                logger.warning("JWKS refresh failed (%s); using cached keys age=%.1fs", e, age)
            else:
                logger.error("JWKS refresh failed and no cache available: %s", e)
                raise

    return cache["jwks"]

def verify_bearer_token(token: str) -> Dict[str, Any]:
    try:
        jwks = fetch_jwks_cached()
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = next((k for k in jwks.get("keys", []) if kid and k.get("kid") == kid), None)
        if key is None and kid is None and len(jwks.get("keys", [])) == 1:
            key = jwks["keys"][0]
        if not key:
            raise ValueError(f"no matching jwk kid={kid}")

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        return jwt.decode(token, key=public_key, algorithms=["RS256"], audience="time_device", issuer=ISSUER)
    except Exception as e:
        kid = None
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except Exception:
            pass
        fp = token[:16] + "..." + token[-16:] if token and len(token) > 40 else "<short>"
        logger.warning("Token verify failed: ip=%s kid=%s aud=%s iss=%s fp=%s err=%s", request.remote_addr, kid, "time_device", ISSUER, fp, e)
        raise

@app.get("/")
def home():
    return jsonify({"service": "time_device", "status": "ok"})
    
@app.post("/escape")
def escape():
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return jsonify({"error": "missing bearer"}), 401
    token = auth.split(None, 1)[1].strip()

    try:
        claims = verify_bearer_token(token)
    except Exception as e:
        logger.warning("Escape denied: token_invalid ip=%s error=%s", request.remote_addr, e)
        return jsonify({"error": "invalid token"}), 401

    username = (claims.get("username") or "").strip()
    
    if "device.control" not in set((claims.get("scope") or "").split()): 
        logger.info("Escape denied: missing_scope user=%s need=device.control have=%s ip=%s", username, claims.get("scope"), request.remote_addr)
        return jsonify({"error": "insufficient_scope"}), 403


    # Two different outcomes depending on who is holding the token
    if username == "Agent404":
        logger.info("Escape success: user=%s client_id=%s scope=%s ip=%s", username, claims.get("client_id"), claims.get("scope"), request.remote_addr)
        return jsonify(
            {
                "ok": True,
                "message": "You hear cavemen screaming in the distance, no doubt shocked by the sudden flash of the time device tearing reality... and the loss of their supper! Time for you to extract as well.",
                "challenge_token": os.environ.get("PREHISTORIC_TOKEN"),
                "claims": {
                    "sub": claims.get("sub"),
                    "username": claims.get("username"),
                    "scope": claims.get("scope"),
                    "client_id": claims.get("client_id"),
                },
            }
        )

    if username == "Agent127":
        # Player gets blocked / guilt-tripped
        logger.info("Escape blocked: user=%s reason=partner_not_extracted client_id=%s scope=%s ip=%s", username, claims.get("client_id"), claims.get("scope"), request.remote_addr)
        return jsonify(
            {
                "ok": False,
                "message": "Whoa whoa whoa! This is YOUR time watch! You can't leave yet! Your partner is still trapped!",
                "claims": {
                    "sub": claims.get("sub"),
                    "username": claims.get("username"),
                    "scope": claims.get("scope"),
                    "client_id": claims.get("client_id"),
                },
            }
        ), 403

    # Unknown/unsupported user
    logger.warning("Escape denied: unknown_user user=%s client_id=%s scope=%s ip=%s", username, claims.get("client_id"), claims.get("scope"), request.remote_addr)
    return jsonify(
        {
            "ok": False,
            "error": "unknown user",
            "claims": {
                "sub": claims.get("sub"),
                "username": claims.get("username"),
                "scope": claims.get("scope"),
                "client_id": claims.get("client_id"),
            },
        }
    ), 403

