#!/usr/bin/env python3
import sys, os, json, base64, hashlib, hmac
import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib as hh

# Parameters must match the server exactly
SALT  = b"HPKE-STEP3-SALT"
INFO  = b"HPKE-STEP3-CTX"
LBL_K = b"HPKE-STEP3-KEY"
LBL_N = b"HPKE-STEP3-NONCE"

def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, hh.sha256).digest()
def hkdf_expand(prk, info, L): return hmac.new(prk, info + b"\x01", hh.sha256).digest()[:L]
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)

def must_file(p):
    ap = os.path.abspath(p)
    if not os.path.isfile(ap):
        d = os.path.dirname(ap) or "."
        try:
            listing = os.listdir(d)
        except Exception:
            listing = []
        raise SystemExit(f"[ERR] Missing file: {ap}\nDir {d} contains: {listing}")
    return ap

def parse_args(argv):
    if len(argv) == 3:
        base, pem = argv[1], must_file(argv[2])              # combined PEM
        return base, pem, None
    elif len(argv) == 4:
        base, crt, key = argv[1], must_file(argv[2]), must_file(argv[3])  # separate files
        return base, crt, key
    else:
        raise SystemExit(f"Usage:\n  {argv[0]} https://webserver /path/client.pem\n"
                         f"  {argv[0]} https://webserver /path/client.crt /path/client.key")

def main():
    base, cert, key = parse_args(sys.argv)
    cert_arg = cert if key is None else (cert, key)

    # 1) Fetch server HPKE public key
    r = requests.get(base + "/hpke/pub", cert=cert_arg, verify=False, timeout=10)
    r.raise_for_status()
    pkR_b64 = r.json()["pkR_b64"]
    pkR = b64d(pkR_b64)

    # 2) Build sealed box for pt = "OPEN-SESAME"
    skE = x25519.X25519PrivateKey.generate()
    pkE = skE.public_key().public_bytes_raw()
    ikm = skE.exchange(x25519.X25519PublicKey.from_public_bytes(pkR))
    prk = hkdf_extract(SALT, ikm)
    key_bytes = hkdf_expand(prk, LBL_K + b"|" + INFO, 32)
    nonce     = hkdf_expand(prk, LBL_N + b"|" + INFO, 12)

    # Bind AAD to your client cert bytes (any AAD accepted by server)
    aad_src = cert if key is None else cert
    aad = hashlib.sha256(open(aad_src,'rb').read()).digest()[:16]

    ct  = ChaCha20Poly1305(key_bytes).encrypt(nonce, b"OPEN-SESAME", aad)
    payload = {"enc": b64e(pkE), "ct": b64e(ct), "aad": b64e(aad)}

    # 3) Submit
    r2 = requests.post(base + "/hpke/unseal", json=payload, cert=cert_arg, verify=False, timeout=10)
    print(r2.status_code, r2.text)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import sys, os, json, base64, hashlib, hmac
import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib as hh

# Parameters must match the server exactly
SALT  = b"HPKE-STEP3-SALT"
INFO  = b"HPKE-STEP3-CTX"
LBL_K = b"HPKE-STEP3-KEY"
LBL_N = b"HPKE-STEP3-NONCE"

def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, hh.sha256).digest()
def hkdf_expand(prk, info, L): return hmac.new(prk, info + b"\x01", hh.sha256).digest()[:L]
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)

def must_file(p):
    ap = os.path.abspath(p)
    if not os.path.isfile(ap):
        d = os.path.dirname(ap) or "."
        try:
            listing = os.listdir(d)
        except Exception:
            listing = []
        raise SystemExit(f"[ERR] Missing file: {ap}\nDir {d} contains: {listing}")
    return ap

def parse_args(argv):
    if len(argv) == 3:
        base, pem = argv[1], must_file(argv[2])              # combined PEM
        return base, pem, None
    elif len(argv) == 4:
        base, crt, key = argv[1], must_file(argv[2]), must_file(argv[3])  # separate files
        return base, crt, key
    else:
        raise SystemExit(f"Usage:\n  {argv[0]} https://webserver /path/client.pem\n"
                         f"  {argv[0]} https://webserver /path/client.crt /path/client.key")

def main():
    base, cert, key = parse_args(sys.argv)
    cert_arg = cert if key is None else (cert, key)

    # 1) Fetch server HPKE public key
    r = requests.get(base + "/hpke/pub", cert=cert_arg, verify=False, timeout=10)
    r.raise_for_status()
    pkR_b64 = r.json()["pkR_b64"]
    pkR = b64d(pkR_b64)

    # 2) Build sealed box for pt = "OPEN-SESAME"
    skE = x25519.X25519PrivateKey.generate()
    pkE = skE.public_key().public_bytes_raw()
    ikm = skE.exchange(x25519.X25519PublicKey.from_public_bytes(pkR))
    prk = hkdf_extract(SALT, ikm)
    key_bytes = hkdf_expand(prk, LBL_K + b"|" + INFO, 32)
    nonce     = hkdf_expand(prk, LBL_N + b"|" + INFO, 12)

    # Bind AAD to your client cert bytes (any AAD accepted by server)
    aad_src = cert if key is None else cert
    aad = hashlib.sha256(open(aad_src,'rb').read()).digest()[:16]

    ct  = ChaCha20Poly1305(key_bytes).encrypt(nonce, b"OPEN-SESAME", aad)
    payload = {"enc": b64e(pkE), "ct": b64e(ct), "aad": b64e(aad)}

    # 3) Submit
    r2 = requests.post(base + "/hpke/unseal", json=payload, cert=cert_arg, verify=False, timeout=10)
    print(r2.status_code, r2.text)

if __name__ == "__main__":
    main()