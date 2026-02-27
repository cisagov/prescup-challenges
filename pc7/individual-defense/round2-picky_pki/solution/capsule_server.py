#!/usr/bin/env python3
import base64, os, hashlib, hmac, requests, cbor2
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CA_BASE = "http://ca_service"
LABEL = b"PKI-CAPSULE-V2"

def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

def obscure64_encode(data: bytes, label: bytes) -> str:
    key = hashlib.sha256(label).digest()
    rot = bytes(b ^ key[i % len(key)] for i, b in enumerate(data[::-1]))
    return base64.urlsafe_b64encode(rot).decode().rstrip("=")

def csr_der_for_cn(cn: str) -> bytes:
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
    pub = requests.get(CA_BASE + "/pubkey", timeout=5).json()
    srv_pub = b64u_decode(pub["x25519_srp_b64"])
    srv_pubkey = x25519.X25519PublicKey.from_public_bytes(srv_pub)

    ep = x25519.X25519PrivateKey.generate()
    epk = ep.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

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

    csr_der = csr_der_for_cn("webserver")
    ct = ChaCha20Poly1305(akey).encrypt(nonce_final, csr_der, None)
    mac = hmac.new(mkey, raw_nonce + ct + context, hashlib.sha256).digest()
    digest = hashlib.sha256(context + epk + raw_nonce + ct).digest()
    sig = edsk.sign(digest)

    capsule = cbor2.dumps({0: epk, 1: raw_nonce, 2: ct, 3: mac, 4: context, 5: sig})
    payload = obscure64_encode(capsule, LABEL)

    r = requests.post(CA_BASE + "/sign-x509", data={"capsule": payload}, timeout=15)
    r.raise_for_status()
    with open("/tmp/server.crt", "wb") as f:
        f.write(r.content)   # bundle: leaf + root
    print("[OK] wrote /tmp/server.crt and /tmp/server.key")

if __name__ == "__main__":
    main()
