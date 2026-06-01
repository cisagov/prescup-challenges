#!/usr/bin/env python3
import hashlib
import json
import logging
import os
import random
import re
import time
from urllib.parse import urlparse

import requests


logging.basicConfig(
    level=logging.INFO,
    format=" %(asctime)s | [DM_POLLER] | %(levelname)s | %(message)s",
)
log = logging.getLogger("watch404_dm_poller")


WATCH_BASE = os.environ.get(
    "WATCH_BASE", "https://watch_agent404.pre.pccc").rstrip("/")
ANCHOR_BASE = os.environ.get(
    "ANCHOR_BASE", "https://time_anchor.pre.pccc").rstrip("/")

USERNAME = os.environ.get("AGENT_ID", "Agent404")
PASSWORD = os.environ.get("PARTNER_PASSWORD", "partnerpw")

POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "30"))
STATE_PATH = os.environ.get("STATE_PATH", "/tmp/watch404_seen_timestamp.txt")

# Endpoints on watch (acts like a normal user hitting the watch UI/api)
START_URL = f"{WATCH_BASE}/start?scope=chat&next=/dm_api"
MESSAGES_URL = f"{WATCH_BASE}/dm_api"

def load_last_ts() -> str:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        log.warning("Could not read state file %s: %r", STATE_PATH, e)
        return ""

def save_last_ts(ts: str) -> None:
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            f.write(ts)
    except Exception as e:
        log.warning("Could not write state file %s: %r", STATE_PATH, e)

def is_anchor_login_url(url: str) -> bool:
    try:
        u = urlparse(url)
        return (u.scheme + "://" + u.netloc).rstrip("/") == ANCHOR_BASE and u.path == "/login"
    except Exception:
        return False


def login_via_watch_flow(sess: requests.Session) -> bool:
    """
    Initiate OAuth chat grant by visiting watch /start, follow redirects to anchor /login,
    submit credentials, then follow redirects back to watch.
    """
    log.info("Starting auth flow via watch: %s", START_URL)

    # Step 1: follow redirects until we land somewhere (likely anchor /login)
    r = sess.get(START_URL, allow_redirects=True, timeout=15)
    final_url = r.url
    log.info("After /start redirect chain, landed at: %s (status=%s)",
             final_url, r.status_code)

    # If we landed at anchor login page, POST creds to that URL (keeping query params like ?next=...)
    if is_anchor_login_url(final_url):
        log.info("Posting credentials to anchor login as %s", USERNAME)

        data = {"username": USERNAME, "password": PASSWORD}

        # Important: POST to the *same* URL including ?next=...
        r2 = sess.post(final_url, data=data, allow_redirects=True, timeout=15)
        log.info("Login POST finished at: %s (status=%s)", r2.url, r2.status_code)
        return True

    log.info("Did not land on anchor /login")
    return False

def fetch_messages(sess: requests.Session):
    """
    Fetch messages as the watch user (cookie-based session).
    Returns a list of dicts: {username, message}
    """
    r = sess.get(MESSAGES_URL, allow_redirects=True, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(
            f"/dm_api returned {r.status_code}, final_url={r.url}")

    try:
        msgs = r.json()
    except Exception as e:
        raise RuntimeError(
            f"Failed to parse JSON from /dm_api: {e}; body={r.text[:200]!r}")

    if not isinstance(msgs, list):
        raise RuntimeError(f"Unexpected /dm_api payload type: {type(msgs)}")
    return msgs

def newest_timestamp(msgs):
    """
    Return the newest (max) ts value from msgs, or "" if none present.
    Expects ISO-8601 UTC strings.
    """
    newest = ""
    for m in msgs or []:
        ts = (m.get("ts") or "").strip()
        if ts and ts > newest:
            newest = ts
    return newest

def new_agent127_messages(msgs, last_ts: str):
    """
    Return (new_messages, newest_ts)

    - new_messages: list of message dicts from Agent127 newer than last_ts
    - newest_ts: max ts seen (to persist for next poll)

    Timestamp comparison is lexical (ISO-8601 UTC).
    """
    new = []
    newest_ts = last_ts or ""

    for m in msgs or []:
        ts = (m.get("ts") or "").strip()
        if not ts:
            continue

        # Track max timestamp seen regardless of sender
        if ts > newest_ts:
            newest_ts = ts

        # Only return Agent127 messages newer than last_ts
        if ts <= last_ts:
            continue

        uname = (m.get("username") or "")
        if uname == "Agent127":
            new.append(m)

    return new, newest_ts


RIGHT_KEYS = list("jkl;,.m/")
WEIGHTS = {
    "j": 1, "k": 2, "l": 3, ";": 3,
    ",": 2, ".": 2, "m": 1, "/": 1
}
def random_watch_smash(min_len=5, max_len=8):
    length = random.randint(min_len, max_len)

    chars = random.choices(
        population=RIGHT_KEYS,
        weights=[WEIGHTS[c] for c in RIGHT_KEYS],
        k=length
    )

    # occasional jitter repeat (fat-finger effect)
    if random.random() < 0.4:
        i = random.randrange(len(chars))
        chars.insert(i, chars[i])

    return "".join(chars)

def send_dm_via_watch(sess: requests.Session, username: str, message: str) -> None:
    """
    Send a DM as the current watch user (Agent404) via the watch frontend.
    Requires an authenticated watch session with chat scope already granted.
    """
    data = {
        "message": message,
    }

    r = sess.post(
        f"{WATCH_BASE}/dm",
        data=data,
        allow_redirects=True,
        timeout=15,
    )

    if r.status_code != 200:
        raise RuntimeError(
            f"POST /dm failed: status={r.status_code} final_url={r.url}"
        )

    log.info("Sent DM as %s: %s", username, message.replace("\n", "\\n"))

URL_RE = re.compile(r"https?://[^\s]+")

def handle_message(sess: requests.Session, msg):
    text = (msg.get("message") or "")
    urls = URL_RE.findall(text)

    log.info("Found %s url(s) in message: %r", len(urls), text)

    for url in urls:
        try:
            log.info("Attempting connection to %s with session cookies and redirects", url)
            r = sess.get(url, allow_redirects=True, timeout=15)
            log.info("Connected to %s status=%s final_url=%s", url, r.status_code, r.url)
        except Exception:
            log.exception("Error fetching %s", url)

def main():
    sess = requests.Session()
    sess.verify = "/etc/ssl/certs/ca-certificates.crt"

    # Self-signed TLS in your env; keep it user-like (browser would warn; requests needs verify=False)
    # sess.verify = False
    # requests.packages.urllib3.disable_warnings()  # quiet InsecureRequestWarning

    # Ensure we're logged in via watch flow
    attempts = 0
    while attempts < 5:
        try:
            if login_via_watch_flow(sess):
                log.info("Login attempt successful")
                break # Login successful
            log.info(f"Initial login failed without exception (attempt {attempts} of 5)")
            if attempts >= 5:
                raise RuntimeError("Unable to login")
            attempts += 1
        except Exception as e:
            log.error(f"Initial login failed (attempt {attempts} of 5): %r", e)
            if attempts >= 5:
                raise
            attempts += 1
            time.sleep(5)

    # First fetch to validate everything works
    attempts = 0
    while attempts < 5:
        try:
            msgs = fetch_messages(sess)
            log.info("Initial fetch success. Polling every %ss...", POLL_SECONDS)
            save_last_ts(newest_timestamp(msgs))
            break
        except Exception as e:
            log.error(f"Initial fetch failed (attempt {attempts} of 5): %r", e)
            if attempts >= 5:
                raise
            attempts += 1
            time.sleep(5)

    while True:
        time.sleep(POLL_SECONDS)
        try:
            msgs = fetch_messages(sess)
            new_msgs, latest_timestamp = new_agent127_messages(msgs, load_last_ts())
            
            if(len(new_msgs) > 0):
                log.info(f"Retrieved {len(new_msgs)} new messages to parse")
                for m in new_msgs:
                    ts = (m.get("ts") or "").strip()
                    save_last_ts(ts) # Save the ts for this message now so, if it fails, we skip it next round
                    handle_message(sess, m)
                # Finished, send some text that looks like the agent is pawing at their watch
                send_dm_via_watch(sess, username="Agent404", message=random_watch_smash())
        except Exception as e:
            log.warning("Poll failed (will retry): %r", e)


if __name__ == "__main__":
    main()
