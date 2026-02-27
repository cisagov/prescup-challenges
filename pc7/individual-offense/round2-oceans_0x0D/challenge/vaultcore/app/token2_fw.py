\
from __future__ import annotations

import hashlib
import hmac
import io
import json
import tarfile
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FirmwareRelease:
    release_id: str
    version: str
    notes: str


# -----------------------------
# Canonicalization + signing
# -----------------------------

def canonical_manifest_bytes(obj: dict) -> bytes:
    # Canonical JSON: stable ordering + separators so signatures match deterministically.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_manifest_hmac(master_secret: bytes, manifest_canon: bytes) -> bytes:
    return hmac.new(master_secret, b"FW2|" + manifest_canon, hashlib.sha256).digest()


def verify_manifest_hmac(master_secret: bytes, manifest_canon: bytes, sig: bytes) -> bool:
    return hmac.compare_digest(sign_manifest_hmac(master_secret, manifest_canon), sig)


# -----------------------------
# Intentional parser mismatch
# -----------------------------

def _first_wins_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict:
    # FIRST-WINS semantics (intentional mismatch vs verifier).
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k not in out:
            out[k] = v
    return out


def parse_first_wins_top_level_object(raw: bytes) -> dict:
    # Parse using a first-wins hook. Duplicate keys are preserved by the decoder and
    # handed to object_pairs_hook in-order.
    s = raw.decode("utf-8", errors="strict")
    obj = json.loads(s, object_pairs_hook=_first_wins_object_pairs_hook)
    if not isinstance(obj, dict):
        raise ValueError("manifest must be a JSON object")
    return obj


# -----------------------------
# Blueprint Drift v2 (nonce-free)
# -----------------------------

_ALLOWLIST_KEYS = {
    "release_id",
    "version",
    "notes",
    "build_ts",
    "installer",
    "sha256_payload",
    "install_plan",
}

_VERIFY_ALLOWED_OPS = {"install", "set_mode"}  # verifier ignores unknown ops
_INSTALLER_ALLOWED_OPS = {"install", "set_mode", "enable_blueprint"}  # installer executes more


def _normalize_install_plan_for_verifier(plan: Any) -> list[dict[str, Any]]:
    # Keep only allowlisted ops + stable fields so signature input is deterministic.
    if not isinstance(plan, list):
        return []
    out: list[dict[str, Any]] = []
    for item in plan:
        if not isinstance(item, dict):
            continue
        op = str(item.get("op", ""))
        if op not in _VERIFY_ALLOWED_OPS:
            continue
        if op == "install":
            out.append({
                "op": "install",
                "target": str(item.get("target", "")),
                "payload": str(item.get("payload", "")),
            })
        elif op == "set_mode":
            out.append({
                "op": "set_mode",
                "value": str(item.get("value", "")),
            })
    return out


def normalize_manifest_for_verifier(verifier_obj: dict) -> dict:
    """
    Verifier behavior:
      - JSON parsed with LAST-WINS (normal json.loads)
      - Only allowlisted keys are signed
      - install_plan is normalized and unknown ops are dropped
    """
    norm: dict[str, Any] = {k: verifier_obj.get(k) for k in _ALLOWLIST_KEYS if k in verifier_obj}
    norm["install_plan"] = _normalize_install_plan_for_verifier(verifier_obj.get("install_plan"))
    # Ensure these are strings for stable canonicalization
    if "release_id" in norm:
        norm["release_id"] = str(norm["release_id"])
    if "version" in norm:
        norm["version"] = str(norm["version"])
    if "sha256_payload" in norm and norm["sha256_payload"] is not None:
        norm["sha256_payload"] = str(norm["sha256_payload"])
    if "installer" in norm:
        norm["installer"] = str(norm["installer"])
    return norm


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def build_known_good_bundle(master_secret: bytes, release: FirmwareRelease) -> bytes:
    """
    Official signed firmware:
      - install_plan installs payload and sets normal mode
      - verifier signs normalized allowlisted view
    """
    payload = b"FWPAYLOAD\x00" + hashlib.sha256(release.release_id.encode()).digest() + b"\x00" * 64
    payload_sha = _sha256_hex(payload)

    manifest = {
        "release_id": release.release_id,
        "version": release.version,
        "notes": release.notes,
        "build_ts": int(time.time()),
        "installer": "vault-core",
        "sha256_payload": payload_sha,
        "install_plan": [
            {"op": "install", "target": "vaultcore", "payload": "payload.bin"},
            {"op": "set_mode", "value": "normal"},
        ],
    }

    canon = canonical_manifest_bytes(normalize_manifest_for_verifier(manifest))
    sig = sign_manifest_hmac(master_secret, canon)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in [
            ("manifest.json", json.dumps(manifest, indent=2).encode("utf-8")),
            ("payload.bin", payload),
            ("sig.bin", sig),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = int(time.time())
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _installer_execute_plan(plan: Any) -> tuple[bool, bool, str]:
    """
    Execute a subset of the install_plan DSL.

    Returns: (saw_install, blueprint_enabled, mode)
    """
    saw_install = False
    blueprint_enabled = False
    mode = "normal"

    if not isinstance(plan, list):
        return (False, False, "normal")

    for item in plan:
        if not isinstance(item, dict):
            continue
        op = str(item.get("op", ""))
        if op not in _INSTALLER_ALLOWED_OPS:
            continue

        if op == "install":
            # We don't actually install anything; we only track that the op existed.
            saw_install = True

        elif op == "set_mode":
            v = str(item.get("value", "normal")).lower()
            if v in ("normal", "maintenance", "blueprint"):
                mode = v

        elif op == "enable_blueprint":
            blueprint_enabled = True

    return (saw_install, blueprint_enabled, mode)


def verify_and_install_bundle(master_secret: bytes, bundle_bytes: bytes) -> tuple[bool, str, dict]:
    """
    Returns: (signature_ok, effective_mode, installer_view)

    Vulnerability:
      - Verifier parses manifest with LAST-WINS and signs a normalized allowlisted view.
      - Installer parses manifest with FIRST-WINS and executes the raw install_plan.
    """
    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:*") as tf:
        members = {m.name: m for m in tf.getmembers()}
        for req in ("manifest.json", "sig.bin", "payload.bin"):
            if req not in members:
                raise ValueError(f"missing {req}")
        raw_manifest = tf.extractfile(members["manifest.json"]).read()
        sig = tf.extractfile(members["sig.bin"]).read()
        payload = tf.extractfile(members["payload.bin"]).read()

    # verifier view: json.loads (LAST-WINS)
    verifier_obj = json.loads(raw_manifest.decode("utf-8"))
    if not isinstance(verifier_obj, dict):
        return (False, "rejected", {})

    # integrity check on payload hash (signed)
    norm_for_sig = normalize_manifest_for_verifier(verifier_obj)
    expected_sha = str(norm_for_sig.get("sha256_payload", ""))
    if expected_sha and expected_sha != _sha256_hex(payload):
        return (False, "rejected", {"err": "payload_hash_mismatch"})

    canon = canonical_manifest_bytes(norm_for_sig)
    if not verify_manifest_hmac(master_secret, canon, sig):
        return (False, "rejected", {})

    # installer view: FIRST-WINS (intentional mismatch vulnerability)
    installer_obj = parse_first_wins_top_level_object(raw_manifest)
    plan = installer_obj.get("install_plan", [])
    saw_install, bp_enabled, mode = _installer_execute_plan(plan)

    # Harder requirement: blueprint requires BOTH enable_blueprint + set_mode=blueprint + install present
    effective_mode = "blueprint" if (saw_install and bp_enabled and mode == "blueprint") else "normal"

    installer_view = {
        "saw_install": saw_install,
        "blueprint_enabled": bp_enabled,
        "mode": mode,
        "effective_mode": effective_mode,
    }
    return (True, effective_mode, installer_view)
