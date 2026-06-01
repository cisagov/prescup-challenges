#!/usr/bin/env bash
set -euo pipefail

mkdir -p /app/ca
cd /app/ca

# If CA already exists, keep it
if [ -f ca.key ] && [ -f ca.crt ]; then
  echo "[ca_init] CA key and cert already exist; skipping generation"
  exit 0
fi

echo "[ca_init] generating RSA CA key/cert (unencrypted PEM) via Python..."

python3 - <<'PY'
import os, datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    Name, NameAttribute, BasicConstraints, SubjectKeyIdentifier,
    AuthorityKeyIdentifier, KeyUsage
)

OUT = "/app/ca"
os.makedirs(OUT, exist_ok=True)

# 1) RSA private key (unencrypted PKCS#8)
sk = rsa.generate_private_key(public_exponent=65537, key_size=4096)
sk_pem = sk.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# 2) Self-signed CA certificate
subject = issuer = Name([NameAttribute(NameOID.COMMON_NAME, u"PickyPKI Root CA")])
now = datetime.datetime.utcnow()

builder = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(sk.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))  # ~10 years
    .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    ), critical=True)
    .add_extension(SubjectKeyIdentifier.from_public_key(sk.public_key()), critical=False)
)

builder = builder.add_extension(AuthorityKeyIdentifier(
    key_identifier=SubjectKeyIdentifier.from_public_key(sk.public_key()).digest,
    authority_cert_issuer=None,
    authority_cert_serial_number=None
), critical=False)

cert = builder.sign(private_key=sk, algorithm=hashes.SHA256())

with open(os.path.join(OUT, "ca.key"), "wb") as f: f.write(sk_pem)
with open(os.path.join(OUT, "ca.crt"), "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

# Minimal state for toy CRL
open(os.path.join(OUT, "revoked.txt"), "w").close()
with open(os.path.join(OUT, "crl.pem"), "w") as f:
    f.write("-----BEGIN PSEUDO-CRL-----\n-----END PSEUDO-CRL-----\n")
open(os.path.join(OUT, "index.txt"), "w").close()
with open(os.path.join(OUT, "serial"), "w") as f: f.write("1000\n")

print("[ca_init:python] wrote unencrypted RSA ca.key and ca.crt to /app/ca")
PY
