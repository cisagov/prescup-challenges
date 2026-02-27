#!/usr/bin/env python3
from flask import Flask, request, jsonify, Response
import os, base64, hmac, hashlib, time
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.url_map.strict_slashes = False

# Public (non-secret) KDF labels – OK to know these
SALT  = b"HPKE-STEP3-SALT"
INFO  = b"HPKE-STEP3-CTX"
LBL_K = b"HPKE-STEP3-KEY"
LBL_N = b"HPKE-STEP3-NONCE"

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, L: int) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:L]

b64e = lambda b: base64.b64encode(b).decode("ascii")
b64d = lambda s: base64.b64decode(s.encode("ascii"))

def derive_bytes(seed_env: str, label: bytes, n: int = 32) -> bytes:
    seed = os.environ.get(seed_env, "")
    seed_bytes = seed.encode("utf-8") if seed else os.urandom(32)
    return hmac.new(label, seed_bytes, hashlib.sha256).digest()[:n]

# Derive stable keys from secrets that exist ONLY in this container
hpke_seed = derive_bytes("ORACLE_HPKE_SEED", b"HPKE-SEED", 32)
sign_seed = derive_bytes("ORACLE_SIGN_SEED", b"SIGN-SEED", 32)

# X25519 decryption key (HPKE receiver)
SKR = x25519.X25519PrivateKey.from_private_bytes(hmac.new(b"skR", hpke_seed, hashlib.sha256).digest())
PKR = SKR.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Ed25519 signing key (for success token)
SKS = ed25519.Ed25519PrivateKey.from_private_bytes(hmac.new(b"skS", sign_seed, hashlib.sha256).digest())
PKS = SKS.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

@app.get("/hpke/pub")
def hpke_pub():
    # Public info (safe to expose)
    return jsonify(
        kem="X25519-SHA256-CHACHAPOLY",
        pkR_b64=b64e(PKR),
        sigpub_b64=b64e(PKS),
        suite=b64e(b"X25519-HKDF-SHA256-CHACHA20POLY1305")
    )

@app.post("/hpke/unseal")
def hpke_unseal():
    if not request.is_json:
        return Response("bad json", status=400)
    data = request.get_json()
    for k in ("enc","ct","aad"):
        if k not in data:
            return Response("missing field", status=400)

    try:
        pkE  = x25519.X25519PublicKey.from_public_bytes(b64d(data["enc"]))
        ct   = b64d(data["ct"])
        aad  = b64d(data["aad"])
        ikm  = SKR.exchange(pkE)
        prk  = hkdf_extract(SALT, ikm)
        key  = hkdf_expand(prk, LBL_K + b"|" + INFO, 32)
        nce  = hkdf_expand(prk, LBL_N + b"|" + INFO, 12)
        pt   = ChaCha20Poly1305(key).decrypt(nce, ct, aad)
    except Exception:
        return Response("decrypt failed", status=403)

    if pt != b"OPEN-SESAME":
        return Response("bad message", status=403)

    # Success: return tamper-evident token (flag + detached signature)
    ts = int(time.time())
    msg = b"HPKE-OK|" + pkE.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) + b"|" + aad + b"|" + str(ts).encode("ascii")
    digest = hashlib.sha256(msg).digest()
    sig = SKS.sign(digest)

    # Success: return token3 from environment (fallback empty string if unset)
    token3 = os.environ.get("token3", "")

    return jsonify(
        token3=token3,
        ts=ts,
        sig_b64=b64e(sig),
        sigpub_b64=b64e(PKS)  # public; grader pins separately
    )

@app.get("/healthz")
def health():
    return jsonify(ok=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
