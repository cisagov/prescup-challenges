#!/usr/bin/env python3
import os, base64, hmac, hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from flask import Flask, request, jsonify, Response
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import cbor2

app = Flask(__name__)
app.url_map.strict_slashes = False

# ---------- Config (Step-1 compatible) ----------
LABEL = b"PKI-CAPSULE-V2"
SERVICE_NAME = "PickyPKI CA"             # unchanged for Step 1
OCSP_PATH = os.environ.get("CA_OCSP_PATH", "/ocsp")
HOST = os.environ.get("CA_SERVICE_HOST", "ca_service")
PORT = int(os.environ.get("PORT", "80")) # internal port stays 80
BASE_OCSP_URI = f"http://{HOST}:{PORT}{OCSP_PATH}"
CA_DIR = os.environ.get("CA_DIR", "/app/ca")
NOW = lambda: datetime.now(timezone.utc)

# ---------- In-memory CA state ----------
ROOT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=4096)
ROOT_SUBJ = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"PickyPKI Root CA")])

ROOT_CERT = (
    x509.CertificateBuilder()
    .subject_name(ROOT_SUBJ)
    .issuer_name(ROOT_SUBJ)
    .public_key(ROOT_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOW() - timedelta(days=1))
    .not_valid_after(NOW() + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, key_encipherment=True, content_commitment=True,
        data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
        encipher_only=False, decipher_only=False), critical=True)
    .sign(ROOT_KEY, hashes.SHA256())
)

# Static X25519 key for capsule DH
X_STATIC = x25519.X25519PrivateKey.generate()
X_STATIC_PUB = X_STATIC.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)

# serial -> (cert, is_server, status)
ISSUED: Dict[int, Tuple[x509.Certificate, bool, str]] = {}

def _log(msg: str): print(msg, flush=True)

# ---------- Test vector (generated once at startup for /pubkey) ----------
def _build_test_vector() -> dict:
    """Build a sample capsule from known inputs so competitors can reverse-engineer
    the wire format, MAC construction, and signature digest by working backward."""
    b64h = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")

    # Fixed ephemeral keys (NOT used for real signing — test vector only)
    tv_epk_priv = x25519.X25519PrivateKey.generate()
    tv_epk = tv_epk_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    tv_edsk = ed25519.Ed25519PrivateKey.generate()
    tv_edpk = tv_edsk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    tv_context = bytes([0x01]) + tv_edpk

    # Derive keys the same way decrypt_capsule does
    shared = X_STATIC.exchange(tv_epk_priv.public_key())
    salt = hashlib.sha256(b"picky" + X_STATIC_PUB + tv_epk).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"capsule-v2").derive(shared)
    akey, mkey = okm[:32], okm[32:]

    # A small dummy plaintext (NOT a real CSR — just for the test vector)
    plaintext = b"TEST-VECTOR-PAYLOAD"

    tv_raw_nonce = os.urandom(12)
    nonce_base = hashlib.sha256(b"n:" + tv_context + tv_epk).digest()[:12]
    nonce_final = bytes(a ^ b for a, b in zip(nonce_base, tv_raw_nonce))

    ct = ChaCha20Poly1305(akey).encrypt(nonce_final, plaintext, None)
    mac = hmac.new(mkey, tv_raw_nonce + ct + tv_context, hashlib.sha256).digest()
    digest = hashlib.sha256(tv_context + tv_epk + tv_raw_nonce + ct).digest()
    sig = tv_edsk.sign(digest)

    cbor_bytes = cbor2.dumps({0: tv_epk, 1: tv_raw_nonce, 2: ct, 3: mac, 4: tv_context, 5: sig})

    # Obscure64 encode
    xor_key = hashlib.sha256(LABEL).digest()
    reversed_bytes = cbor_bytes[::-1]
    xored = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(reversed_bytes))
    obscure64_str = base64.urlsafe_b64encode(xored).decode().rstrip("=")

    return {
        "description": "A complete capsule built from the values below. Reverse-engineer the encoding by comparing fields to the final wire output.",
        "plaintext_hex": plaintext.hex(),
        "fields": {
            "epk_raw_hex": tv_epk.hex(),
            "raw_nonce_hex": tv_raw_nonce.hex(),
            "ct_hex": ct.hex(),
            "mac_hex": mac.hex(),
            "context_hex": tv_context.hex(),
            "sig_hex": sig.hex(),
        },
        "cbor_hex": cbor_bytes.hex(),
        "wire_output": obscure64_str,
    }

TEST_VECTOR = _build_test_vector()

# ---------- Capsule helpers ----------
def obscure64_decode(s: str, label: bytes) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    raw = base64.urlsafe_b64decode(s + pad)
    key = hashlib.sha256(label).digest()
    rot = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return rot[::-1]

def decrypt_capsule(payload: str) -> bytes:
    blob = obscure64_decode(payload, LABEL)
    m = cbor2.loads(blob)
    epk = m[0]; raw_nonce = m[1]; ct = m[2]; mac = m[3]; context = m[4]; sig = m[5]

    ep_pub = x25519.X25519PublicKey.from_public_bytes(epk)
    shared = X_STATIC.exchange(ep_pub)
    salt = hashlib.sha256(b"picky" + X_STATIC_PUB + epk).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"capsule-v2").derive(shared)
    akey, mkey = okm[:32], okm[32:]

    nonce_base = hashlib.sha256(b"n:" + context + epk).digest()[:12]
    nonce_final = bytes(a ^ b for a, b in zip(nonce_base, raw_nonce))

    expect_mac = hmac.new(mkey, raw_nonce + ct + context, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect_mac):
        raise ValueError("Bad capsule MAC")

    digest = hashlib.sha256(context + epk + raw_nonce + ct).digest()
    if not (len(context) > 1 and context[0] == 0x01):
        raise ValueError("Bad context")
    edpk = ed25519.Ed25519PublicKey.from_public_bytes(context[1:])
    edpk.verify(sig, digest)

    csr_der = ChaCha20Poly1305(akey).decrypt(nonce_final, ct, None)
    return csr_der

def sign_cert_from_csr(csr: x509.CertificateSigningRequest) -> x509.Certificate:
    # Heuristic: CN containing 'grader' or 'client' -> clientAuth else serverAuth
    cn = None
    for a in csr.subject:
        if a.oid == NameOID.COMMON_NAME:
            cn = a.value; break
    is_server = not (cn and (("grader" in cn.lower()) or ("client" in cn.lower())))

    b = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ROOT_SUBJ)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW() - timedelta(minutes=2))
        .not_valid_after(NOW() + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ROOT_KEY.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH
        ]), critical=False)
        .add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(BASE_OCSP_URI))
        ]), critical=False)
    )
    # Must-Staple only for server certs
    if is_server:
        b = b.add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)

    cert = b.sign(ROOT_KEY, hashes.SHA256())
    ISSUED[cert.serial_number] = (cert, is_server, "good")
    return cert

def persist_ca_files():
    try:
        os.makedirs(CA_DIR, exist_ok=True)
        with open(os.path.join(CA_DIR, "ca.key"), "wb") as f:
            f.write(ROOT_KEY.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(os.path.join(CA_DIR, "ca.crt"), "wb") as f:
            f.write(ROOT_CERT.public_bytes(serialization.Encoding.PEM))
        _log("[ca_init:python] wrote unencrypted RSA ca.key and ca.crt to /app/ca")
    except Exception as e:
        _log(f"[ca_init:python] WARNING: persist failed: {e}")

# ---------- Endpoints ----------
@app.get("/")
def root(): return jsonify(service=SERVICE_NAME)

@app.get("/pubkey")
def pubkey():
    """Step-1 compatible: keeps `x25519_srp_b64` stable and adds a protocol disclosure surface."""
    b64 = base64.urlsafe_b64encode(X_STATIC_PUB).decode().rstrip("=")

    capsule = {
        "label": LABEL.decode("ascii", "replace"),
        "version": 2,
        "kdf": {
            "name": "HKDF",
            "hash": "SHA-256",
            "length_bytes": 64,
            "salt_recipe": "salt = SHA256( b\"picky\" || X_STATIC_PUB_RAW || epk_raw )",
            "info": "capsule-v2",
            "expand": "okm[0:32]=akey, okm[32:64]=mkey",
        },
        "nonce": {
            "aead": "ChaCha20-Poly1305",
            "raw_nonce_len_bytes": 12,
            "base_recipe": "nonce_base = SHA256( b\"n:\" || context || epk_raw )[0:12]",
            "final_recipe": "nonce_final = nonce_base XOR raw_nonce",
        },
        "context": {
            "layout": "context = 0x01 || ed25519_public_key_raw(32 bytes)",
            "constraints": [
                "len(context) > 1",
                "context[0] == 0x01",
            ],
        },
        "integrity": {
            "algorithms": ["HMAC-SHA256", "Ed25519"],
            "hint": "The capsule includes both a MAC (using mkey) and a signature (using the ed25519 key from context). Study the test vector to determine the exact constructions."
        },
        "wire_format": {
            "serialization": "CBOR",
            "encoding": "custom",
            "hint": "The CBOR payload is obfuscated before transmission. Compare cbor_hex to wire_output in the test vector to reverse-engineer the encoding."
        },
    }

    return jsonify(x25519_srp_b64=b64, capsule=capsule, test_vector=TEST_VECTOR)

@app.get("/ca.crt")
def ca_crt():
    return Response(ROOT_CERT.public_bytes(serialization.Encoding.PEM), mimetype="application/x-pem-file")

@app.post("/sign-x509")
def sign():
    capsule = request.form.get("capsule")
    if not capsule:
        return Response("missing capsule", status=400)
    try:
        csr_der = decrypt_capsule(capsule)
        csr = x509.load_der_x509_csr(csr_der)
        cert = sign_cert_from_csr(csr)
        pem = cert.public_bytes(serialization.Encoding.PEM)
        # return bundle leaf+root
        bundle = pem + ROOT_CERT.public_bytes(serialization.Encoding.PEM)
        return Response(bundle, mimetype="application/x-pem-file")
    except Exception as e:
        return Response(f"bad capsule: {e}", status=400)

@app.post("/ocsp")
def ocsp_responder():
    try:
        req = ocsp.load_der_ocsp_request(request.data)
        serial = req.serial_number
        if serial not in ISSUED:
            resp = ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)
            return Response(resp.public_bytes(serialization.Encoding.DER), mimetype="application/ocsp-response")
        cert, is_server, status = ISSUED[serial]
        this = NOW(); nextu = this + timedelta(days=1)
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=cert, issuer=ROOT_CERT, algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD if status == "good" else ocsp.OCSPCertStatus.REVOKED,
            this_update=this, next_update=nextu, revocation_time=None, revocation_reason=None
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ROOT_CERT)
        resp = builder.sign(private_key=ROOT_KEY, algorithm=hashes.SHA256())
        return Response(resp.public_bytes(serialization.Encoding.DER), mimetype="application/ocsp-response")
    except Exception:
        resp = ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
        return Response(resp.public_bytes(serialization.Encoding.DER), mimetype="application/ocsp-response")

# ---------- Main ----------
if __name__ == "__main__":
    persist_ca_files()
    app.run(host="0.0.0.0", port=PORT)