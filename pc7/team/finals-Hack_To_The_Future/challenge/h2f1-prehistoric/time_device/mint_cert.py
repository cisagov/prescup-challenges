#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import NamedTemporaryFile

PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----"


def log(msg: str) -> None:
    print(msg, flush=True)


def getenv_required(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise SystemExit(f"[!] Missing {name}")
    return val


def run(cmd: list[str]) -> None:
    # stdout/stderr inherited so errors are visible in container logs
    subprocess.run(cmd, check=True)


def http_get(url: str, timeout: float = 3.0) -> bytes:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def http_post_json(url: str, payload: dict, timeout: float = 5.0) -> tuple[int, bytes]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        # still read the body so we can log it
        body = e.read()
        return e.code, body


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("wb", delete=False, dir=str(path.parent)) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, path)
    if mode is not None:
        os.chmod(path, mode)


def maybe_install_ca_into_system_trust(ca_cert_path: Path) -> None:
    # Debian/Ubuntu: /usr/local/share/ca-certificates/*.crt + update-ca-certificates
    updater = shutil.which("update-ca-certificates")
    if not updater:
        return

    dst = Path("/usr/local/share/ca-certificates/ctf-ca.crt")
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ca_cert_path, dst)
        # Do not fail hard if this isn't permitted
        subprocess.run([updater], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("[*] Installed CA into system trust store")
    except Exception as e:
        log(f"[*] Could not install CA into trust store (continuing): {e}")


def validate_pem_cert(pem: str) -> str:
    pem = pem.strip()
    if not pem.startswith(PEM_CERT_HEADER):
        raise ValueError("cert_pem missing/invalid (does not start with PEM header)")
    # minimal sanity: must contain END line too
    if "-----END CERTIFICATE-----" not in pem:
        raise ValueError("cert_pem missing END CERTIFICATE line")
    return pem + "\n"


def backoff_sleep(attempt: int, base: float = 1.0, cap: float = 10.0) -> None:
    # exponential backoff capped
    delay = min(cap, base * (2 ** max(0, attempt - 1)))
    time.sleep(delay)


def main() -> int:
    ca_url = "http://ca.pre.pccc:8080"
    host = getenv_required("HOST")

    cert_dir = Path(os.environ.get("CERT_DIR", "/app/certs"))
    cert_file = Path(os.environ.get("CERT_FILE", str(cert_dir / "server.crt")))
    key_file = Path(os.environ.get("KEY_FILE", str(cert_dir / "server.key")))
    csr_file = Path(os.environ.get("CSR_FILE", str(cert_dir / "server.csr")))
    ca_cert_file = Path(os.environ.get("CA_CERT_FILE", str(cert_dir / "ca.crt")))

    cert_dir.mkdir(parents=True, exist_ok=True)

    # 1) Generate key + CSR (always remint)
    log(f"[*] Generating key + CSR for {host}")
    run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_file),
            "-out",
            str(csr_file),
            "-subj",
            f"/CN={host}",
            "-addext",
            f"subjectAltName=DNS:{host}",
        ]
    )

    # 2) Wait for CA and fetch CA cert
    ca_crt_url = f"{ca_url}/ca.crt"
    log(f"[*] Waiting for CA cert at {ca_crt_url}")
    attempt = 1
    while True:
        try:
            ca_bytes = http_get(ca_crt_url)
            if not ca_bytes or PEM_CERT_HEADER.encode() not in ca_bytes:
                raise ValueError("CA cert response was empty or not PEM")
            atomic_write(ca_cert_file, ca_bytes, mode=0o644)
            log(f"[*] Fetched CA cert -> {ca_cert_file}")
            break
        except Exception as e:
            log(f"[*] CA not ready yet ({e}); retrying...")
            backoff_sleep(attempt)
            attempt += 1

    # Optional: install CA into system trust
    maybe_install_ca_into_system_trust(ca_cert_file)

    # 3) Request signed leaf cert (retry until CA is ready + returns valid cert_pem)
    sign_url = f"{ca_url}/sign"
    csr_pem = csr_file.read_text(encoding="utf-8")

    log(f"[*] Requesting signed leaf cert from {sign_url} (retry until ready)")
    attempt = 1
    while True:
        status, body = http_post_json(sign_url, {"csr_pem": csr_pem})
        if 200 <= status < 300:
            try:
                obj = json.loads(body.decode("utf-8", errors="replace"))
                pem = validate_pem_cert(obj.get("cert_pem", ""))
                atomic_write(cert_file, pem.encode("utf-8"), mode=0o644)
                log(f"[*] Wrote signed cert -> {cert_file}")
                break
            except Exception as e:
                log(f"[*] CA response not usable yet ({e}); body:\n{body.decode('utf-8', errors='replace')}")
        else:
            log(f"[*] CA /sign not ready (HTTP {status}); body:\n{body.decode('utf-8', errors='replace')}")

        backoff_sleep(attempt)
        attempt += 1

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("[!] Interrupted")
        raise SystemExit(130)
