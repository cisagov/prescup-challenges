#!/usr/bin/env python3
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from flask import Flask, Response, jsonify, request

# ---- logging (always) ----
logging.basicConfig(
    level=logging.INFO,
    format=" %(asctime)s | [CA] | %(levelname)s | %(message)s",
)
log = logging.getLogger("ca")

app = Flask(__name__)

CERT_DIR = Path(os.environ.get("CERT_DIR", "/app/certs"))
CA_KEY = CERT_DIR / "ca.key"
CA_CRT = CERT_DIR / "ca.crt"
CA_SERIAL = CERT_DIR / "ca.srl"

CA_SUBJECT = os.environ.get("CA_SUBJECT", "/CN=HackToFuturePrehistoricCA")
CA_DAYS = str(int(os.environ.get("CA_DAYS", "7")))
LEAF_DAYS = str(int(os.environ.get("LEAF_DAYS", "7")))


def sh(cmd: list[str]) -> str:
    """Run a command and return combined stdout/stderr. Logs on success/failure."""
    log.info("exec: %s", " ".join(cmd))
    try:
        p = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if p.stdout:
            log.info("output:\n%s", p.stdout.rstrip())
        return p.stdout
    except subprocess.CalledProcessError as e:
        out = e.stdout or ""
        log.error("command failed (rc=%s): %s", e.returncode, " ".join(cmd))
        if out:
            log.error("output:\n%s", out.rstrip())
        raise


def ensure_ca() -> None:
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    if CA_KEY.exists() and CA_CRT.exists():
        log.info("CA already present: key=%s crt=%s", CA_KEY, CA_CRT)
        return

    log.warning("CA not found; generating ephemeral CA in %s", CERT_DIR)

    # Fresh ephemeral CA key + cert
    sh(["openssl", "genrsa", "-out", str(CA_KEY), "2048"])
    sh(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            str(CA_KEY),
            "-sha256",
            "-days",
            CA_DAYS,
            "-out",
            str(CA_CRT),
            "-subj",
            CA_SUBJECT,
        ]
    )

    # Basic sanity log
    sh(["openssl", "x509", "-in", str(CA_CRT), "-noout", "-subject", "-issuer", "-enddate"])


@app.get("/healthz")
def healthz():
    # "ready" means CA exists and is readable
    try:
        ensure_ca()
        if CA_CRT.exists() and CA_CRT.stat().st_size > 0 and CA_KEY.exists() and CA_KEY.stat().st_size > 0:
            return jsonify({"status": "ok"}), 200
    except Exception as e:
        log.exception("healthz failure: %s", e)
    return jsonify({"status": "not_ready"}), 503


@app.get("/ca.crt")
def ca_crt():
    ensure_ca()
    try:
        data = CA_CRT.read_bytes()
        if not data:
            log.error("CA cert file is empty: %s", CA_CRT)
            return jsonify({"error": "ca.crt empty"}), 500
        return Response(data, mimetype="application/x-x509-ca-cert")
    except Exception as e:
        log.exception("failed to serve ca.crt: %s", e)
        return jsonify({"error": "failed to read ca.crt"}), 500


@app.post("/sign")
def sign():
    """
    Accepts JSON:
      { "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."}

    Returns JSON:
      { "cert_pem": "-----BEGIN CERTIFICATE-----..." }
    """
    ensure_ca()

    data = request.get_json(silent=True) or {}
    csr_pem = (data.get("csr_pem") or "").strip()

    if not csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
        log.warning("sign: missing/invalid csr_pem (len=%d)", len(csr_pem))
        return jsonify({"error": "missing/invalid csr_pem"}), 400

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        csr_path = td_path / "req.csr"
        crt_path = td_path / "leaf.crt"

        csr_path.write_text(csr_pem + "\n", encoding="utf-8")

        # Log a quick CSR summary for debugging (includes SAN if present)
        try:
            sh(["openssl", "req", "-in", str(csr_path), "-noout", "-subject", "-text"])
        except Exception:
            # If this fails, signing will fail too; let it propagate below.
            pass

        # NOTE: -copy_extensions copy will copy SAN from CSR. OK for lab/CTF.
        sh(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr_path),
                "-CA",
                str(CA_CRT),
                "-CAkey",
                str(CA_KEY),
                "-CAcreateserial",
                "-CAserial",
                str(CA_SERIAL),
                "-out",
                str(crt_path),
                "-days",
                LEAF_DAYS,
                "-sha256",
                "-copy_extensions",
                "copy",
            ]
        )

        cert_pem = crt_path.read_text(encoding="utf-8").strip()

        if not cert_pem.startswith("-----BEGIN CERTIFICATE-----"):
            log.error("sign: produced non-PEM output (first 80 chars): %r", cert_pem[:80])
            return jsonify({"error": "signing produced invalid certificate"}), 500

        # Extra sanity: log subject/issuer and SAN for the issued leaf
        try:
            sh(["openssl", "x509", "-in", str(crt_path), "-noout", "-subject", "-issuer", "-enddate"])
            sh(["openssl", "x509", "-in", str(crt_path), "-noout", "-text"])
        except Exception:
            pass

    log.info("sign: issued leaf cert (pem_len=%d)", len(cert_pem))
    return jsonify({"cert_pem": cert_pem + "\n"}), 200


if __name__ == "__main__":
    # Flask dev server for container lab use; front with gunicorn if you want.
    host = os.environ.get("BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    log.info("starting CA server on %s:%d (CERT_DIR=%s)", host, port, CERT_DIR)
    app.run(host=host, port=port)
