#!/usr/bin/env python3
import os, socket, time, subprocess, base64, hashlib, hmac
from typing import List, Optional, Tuple

import requests, cbor2
from flask import Flask, Response, jsonify

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from OpenSSL import SSL, crypto

app = Flask(__name__)
app.url_map.strict_slashes = False

# ---------- Config ----------
DEFAULT_TARGET_HOST = os.environ.get("TARGET_HOST", "webserver")
DEFAULT_TARGET_PORT = int(os.environ.get("TARGET_PORT", "443"))
DEFAULT_SNI = os.environ.get("TARGET_SNI", "webserver")

CA_URL = os.environ.get("CA_URL", "http://ca_service")

# Give OpenSSL a little more time; pyOpenSSL handshake retries internally too.
OPENSSL_TIMEOUT = int(os.environ.get("OPENSSL_TIMEOUT", "15"))
PYOPENSSL_TIMEOUT = int(os.environ.get("PYOPENSSL_TIMEOUT", "8"))

LABEL = b"PKI-CAPSULE-V2"

INDEX_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>PKI Grader</title>
<style>
body{font-family:system-ui;background:#0b1020;color:#e7ecf7}
.wrap{max-width:560px;margin:48px auto}
.card{background:#121833;border:1px solid #223;border-radius:12px;padding:22px;text-align:center}
.btn{padding:12px 18px;border-radius:10px;border:1px solid #3a4;background:#1b8f4d;color:#fff;font-weight:700}
pre{background:#0a0f22;border:1px solid #1b2240;border-radius:8px;padding:12px;margin-top:12px;white-space:pre-wrap}
</style></head><body><div class="wrap"><div class="card">
<h2>PKI Grader</h2>
<button id="go" class="btn">Check</button>
<pre id="out">Waiting…</pre>
</div></div>
<script>
const go=document.getElementById('go'), out=document.getElementById('out');
go.onclick=async()=>{go.disabled=true; out.textContent="Checking…";
 try{const r=await fetch('/grade',{method:'POST'}); out.textContent=await r.text();}catch(e){out.textContent="step1: fail\\nstep2: fail";}
 finally{go.disabled=false;}}
</script></body></html>"""

@app.get("/")
def index(): return INDEX_HTML

@app.get("/healthz")
def healthz(): return jsonify(ok=True)

# ---------- Helpers ----------
def resolve_ipv4(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        # de-dup while preserving order
        return list(dict.fromkeys([ai[4][0] for ai in infos if ":" not in ai[4][0]]))
    except Exception:
        return []

def fetch_chain_pyopenssl(host: str, port: int, sni: str, timeout: int = PYOPENSSL_TIMEOUT) -> List[x509.Certificate]:
    """
    Try all resolved IPv4s; return first successful peer chain.
    """
    ips = resolve_ipv4(host)
    last = None
    for ip in ips or [host]:
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
            try: ctx.set_options(SSL.OP_NO_TLSv1_3)  # keep behavior deterministic
            except Exception: pass
            tls = SSL.Connection(ctx, sock)
            if sni: tls.set_tlsext_host_name(sni.encode())
            tls.set_connect_state(); tls.setblocking(1)
            deadline = time.time() + timeout
            while True:
                try:
                    tls.do_handshake()
                    break
                except SSL.WantReadError:
                    if time.time() >= deadline: raise
                    time.sleep(0.05)
            chain = tls.get_peer_cert_chain() or []
            if not chain:
                single = tls.get_peer_certificate()
                if single: chain = [single]
            pem_chain = [crypto.dump_certificate(crypto.FILETYPE_PEM, c) for c in chain]
            try: tls.shutdown()
            except Exception: pass
            tls.close(); sock.close()
            return [x509.load_pem_x509_certificate(p) for p in pem_chain]
        except Exception as e:
            last = e
            time.sleep(0.05)
    raise RuntimeError(f"TLS fetch failed: {last}")

def _cn(name: x509.Name) -> Optional[str]:
    for a in name:
        if a.oid == NameOID.COMMON_NAME:
            return a.value
    return None

def step1_ok(leaf: x509.Certificate) -> bool:
    return (_cn(leaf.subject) == "webserver") and (_cn(leaf.issuer) == "PickyPKI Root CA")

def token_step1(leaf: x509.Certificate) -> str:
    # Award token from environment variable "token1"
    return os.environ.get("token1", "")

def cert_has_must_staple(leaf: x509.Certificate) -> bool:
    try:
        ext = leaf.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE).value
        return x509.TLSFeatureType.status_request in list(ext)
    except x509.ExtensionNotFound:
        return False
    except Exception:
        return False

def try_handshake_without_client_cert(ip_or_host: str, port: int, sni: str, timeout: int = PYOPENSSL_TIMEOUT) -> bool:
    """
    Return True if handshake *succeeds* with no client cert.
    If mTLS is enforced at handshake, this should fail => return False.
    """
    try:
        sock = socket.create_connection((ip_or_host, port), timeout=timeout)
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        try: ctx.set_options(SSL.OP_NO_TLSv1_3)
        except Exception: pass
        ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        tls = SSL.Connection(ctx, sock)
        if sni: tls.set_tlsext_host_name(sni.encode())
        tls.set_connect_state(); tls.setblocking(1)
        deadline = time.time() + timeout
        while True:
            try:
                tls.do_handshake()
                break
            except SSL.WantReadError:
                if time.time() >= deadline: raise
                time.sleep(0.05)
        try: tls.shutdown()
        except Exception: pass
        tls.close(); sock.close()
        return True
    except Exception:
        return False

def http_requires_client_cert(host: str, port: int, sni: str, timeout: int = 6) -> bool:
    """
    As a fallback, some stacks negotiate then error at HTTP layer.
    Treat 495/496/403/401/400 or SSL errors as 'client cert required'.
    """
    try:
        url = f"https://{host}:{port}/"
        r = requests.get(url, headers={"Host": sni}, verify=False, timeout=timeout, allow_redirects=False)
        if r.status_code in (495, 496, 403, 401, 400):
            txt = (r.text or "").lower()
            if ("client certificate" in txt) or ("ssl certificate" in txt) or ("certificate required" in txt):
                return True
        return False
    except requests.exceptions.SSLError:
        return True
    except Exception:
        return False

def obscure64_encode(data: bytes, label: bytes) -> str:
    key = hashlib.sha256(label).digest()
    rot = bytes(b ^ key[i % len(key)] for i, b in enumerate(data[::-1]))
    return base64.urlsafe_b64encode(rot).decode().rstrip("=")

def mint_client_cert(cn: str = "graderclient") -> Tuple[str, str]:
    """
    Capsule client: request a clientAuth cert from the CA and write leaf cert/key to /tmp.
    """
    pub = requests.get(f"{CA_URL}/pubkey", timeout=5).json()
    srv_b64 = pub["x25519_srp_b64"]
    pad = "=" * ((4 - (len(srv_b64) % 4)) % 4)
    srv_pub = base64.urlsafe_b64decode(srv_b64 + pad)
    srv_pubkey = x25519.X25519PublicKey.from_public_bytes(srv_pub)
    ep = x25519.X25519PrivateKey.generate()
    epk = ep.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(pkey, hashes.SHA256()))
    csr_der = csr.public_bytes(serialization.Encoding.DER)

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

    ct = ChaCha20Poly1305(akey).encrypt(nonce_final, csr_der, None)
    mac = hmac.new(mkey, raw_nonce + ct + context, hashlib.sha256).digest()
    digest = hashlib.sha256(context + epk + raw_nonce + ct).digest()
    sig = edsk.sign(digest)

    capsule = cbor2.dumps({0: epk, 1: raw_nonce, 2: ct, 3: mac, 4: context, 5: sig})
    payload = obscure64_encode(capsule, LABEL)

    r = requests.post(f"{CA_URL}/sign-x509", data={"capsule": payload}, timeout=15)
    r.raise_for_status()
    pem_bundle = r.content

    cert_path = "/tmp/grader_client.crt"; key_path = "/tmp/grader_client.key"
    leaf = pem_bundle.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    open(cert_path,"wb").write(leaf)
    open(key_path,"wb").write(
        pkey.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption()))
    return cert_path, key_path

def parse_sclient_status(out: str) -> bool:
    # Look for the two canonical lines emitted by `openssl s_client -status`
    return ("OCSP Response Status: successful" in out) and ("Cert Status: good" in out)

def openssl_status_with_client_cert(ip_or_host: str, port: int, sni: str, cert_path: str, key_path: str,
                                    timeout: int = OPENSSL_TIMEOUT) -> Tuple[bool, str]:
    cmd = [
        "openssl","s_client","-connect",f"{ip_or_host}:{port}",
        "-servername",sni,"-status","-cert",cert_path,"-key",key_path,
        "-tls1_2","-ign_eof"
    ]
    p = subprocess.run(
        cmd, input=b"Q\n", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, check=False
    )
    out = p.stdout.decode("utf-8","replace")
    return parse_sclient_status(out), out

def token_step2(leaf: x509.Certificate, ocsp_text: str) -> str:
    # Award token from environment variable "token2"
    return os.environ.get("token2", "")

# ---------- Grader ----------
@app.post("/grade")
def grade():
    step1_line, step2_line = "step1: fail", "step2: fail"
    try:
        host, port, sni = DEFAULT_TARGET_HOST, DEFAULT_TARGET_PORT, DEFAULT_SNI
        ips = resolve_ipv4(host)

        # ---- STEP 1: chain + issuer/subject check (works even without mTLS) ----
        chain: List[x509.Certificate] = []
        try:
            chain = fetch_chain_pyopenssl(host, port, sni)
        except Exception:
            chain = []

        if chain:
            leaf = chain[0]
            if step1_ok(leaf):
                step1_line = f"step1: pass: {token_step1(leaf)}"

            # ---- STEP 2: must-staple + mTLS + stapled OCSP(good) ----
            try:
                if cert_has_must_staple(leaf):
                    # mTLS must be enforced at *handshake*. Check all IPs.
                    ip_candidates = ips or [host]
                    mtls_proved_somewhere = False
                    working_ip_for_status = None

                    for ip in ip_candidates:
                        mtls_enforced = not try_handshake_without_client_cert(ip, port, sni)
                        if not mtls_enforced:
                            # Fallback probe via HTTPS status codes / SSL error on host (SNI matters)
                            mtls_enforced = http_requires_client_cert(host, port, sni)

                        if mtls_enforced:
                            mtls_proved_somewhere = True
                            working_ip_for_status = ip
                            break

                    if mtls_proved_somewhere and working_ip_for_status:
                        # One request for a client cert is enough; reuse for all
                        cert_path, key_path = mint_client_cert("graderclient")
                        # Try stapled-OCSP on the verified mTLS IP; if it hiccups, try others.
                        for ip in [working_ip_for_status] + [i for i in (ip_candidates) if i != working_ip_for_status]:
                            ok, out = openssl_status_with_client_cert(ip, port, sni, cert_path, key_path)
                            if ok:
                                step2_line = f"step2: pass: {token_step2(leaf, out)}"
                                break
            except Exception:
                # Any unexpected issue keeps step2 as 'fail'
                pass

        return Response(f"{step1_line}\n{step2_line}", mimetype="text/plain")
    except Exception:
        return Response("step1: fail\nstep2: fail", mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
