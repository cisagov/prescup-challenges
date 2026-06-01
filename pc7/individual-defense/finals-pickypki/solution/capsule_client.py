import base64, os, sys, hashlib, hmac, requests, cbor2
from typing import List
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

LABEL = b"PKI-CAPSULE-V2"

def _get_json(url: str, timeout: float = 5.0) -> dict:
    r = requests.get(url, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"GET {url} -> HTTP {r.status_code}, body[:200]={r.text[:200]!r}")
    try:
        return r.json()
    except Exception:
        raise RuntimeError(f"GET {url} content-type={r.headers.get('Content-Type')} not JSON; body[:200]={r.text[:200]!r}")

def _route_exists(base: str) -> None:
    # 1) root must identify as the CA
    root = _get_json(base + "/")
    if root.get("service") != "PickyPKI CA":
        raise RuntimeError(f"{base}/ did not identify as CA: {root!r}")

    # 2) pubkey must present x25519_srp_b64
    pub = _get_json(base + "/pubkey")
    if "x25519_srp_b64" not in pub:
        raise RuntimeError(f"{base}/pubkey missing x25519_srp_b64: {pub!r}")

    # 3) POST /sign-x509 must exist and reply 400 to missing capsule
    r = requests.post(base + "/sign-x509", data={}, timeout=5.0)
    if r.status_code != 400 or "missing capsule" not in r.text:
        raise RuntimeError(f"{base}/sign-x509 preflight failed: HTTP {r.status_code}, body[:200]={r.text[:200]!r}")

def _discover_base() -> str:
    # Allow manual pinning via env var
    env = os.environ.get("CA_URL")
    if env:
        _route_exists(env.rstrip("/"))
        return env.rstrip("/")

    # Strong discovery: try common forms and the DNS IP directly
    candidates: List[str] = [
        "http://ca_service",        # our compose maps CA to port 80 internally
        "http://ca_service:80"
    ]

    # Also try the resolved IPs for 'ca_service', if available
    try:
        import socket
        ips = [ai[4][0] for ai in socket.getaddrinfo("ca_service", None) if ":" not in ai[4][0]]
        for ip in dict.fromkeys(ips):  # de-dup
            candidates += [f"http://{ip}", f"http://{ip}:80", f"http://{ip}:5000"]
    except Exception:
        pass

    last_err = None
    for base in candidates:
        b = base.rstrip("/")
        try:
            _route_exists(b)
            return b
        except Exception as e:
            last_err = e
    raise SystemExit(f"[ERR] Could not locate a valid CA. Last error: {last_err}")

def _obscure64_encode(data: bytes, label: bytes) -> str:
    key = hashlib.sha256(label).digest()
    rot = bytes(b ^ key[i % len(key)] for i, b in enumerate(data[::-1]))
    return base64.urlsafe_b64encode(rot).decode().rstrip("=")

def _csr_der_for_cn(cn: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ).sign(key, hashes.SHA256())
    with open("/tmp/server.key", "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return csr.public_bytes(serialization.Encoding.DER)

def main():
    base = _discover_base()
    print(f"[OK] CA base: {base}")

    pub = _get_json(base + "/pubkey")
    srv_b64 = pub["x25519_srp_b64"]
    pad = "=" * ((4 - (len(srv_b64) % 4)) % 4)
    srv_pub = base64.urlsafe_b64decode(srv_b64 + pad)

    ep = x25519.X25519PrivateKey.generate()
    epk = ep.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    srv_pubkey = x25519.X25519PublicKey.from_public_bytes(srv_pub)

    shared = ep.exchange(srv_pubkey)
    salt = hashlib.sha256(b"picky" + srv_pub + epk).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"capsule-v2").derive(shared)
    akey, mkey = okm[:32], okm[32:]

    edsk = ed25519.Ed25519PrivateKey.generate()
    edpk = edsk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    context = bytes([0x01]) + edpk

    raw_nonce = os.urandom(12)
    nonce_final = hashlib.sha256(b"n:" + context + epk).digest()[:12]
    nonce_final = bytes(a ^ b for a, b in zip(nonce_final, raw_nonce))

    csr_der = _csr_der_for_cn("webserver")
    ct = ChaCha20Poly1305(akey).encrypt(nonce_final, csr_der, None)
    mac = hmac.new(mkey, raw_nonce + ct + context, hashlib.sha256).digest()
    digest = hashlib.sha256(context + epk + raw_nonce + ct).digest()
    sig = edsk.sign(digest)

    capsule = cbor2.dumps({0: epk, 1: raw_nonce, 2: ct, 3: mac, 4: context, 5: sig})
    payload = _obscure64_encode(capsule, LABEL)

    r = requests.post(base + "/sign-x509", data={"capsule": payload}, timeout=10)
    if r.status_code != 200 or b"BEGIN CERTIFICATE" not in r.content:
        raise SystemExit(f"[ERR] Signing failed at {base}/sign-x509: HTTP {r.status_code} | body[:300]={r.text[:300]!r}")

    with open("/tmp/server.crt", "wb") as f:
        f.write(r.content)
    print("[OK] wrote /tmp/server.crt and /tmp/server.key")

if __name__ == "__main__":
    main()