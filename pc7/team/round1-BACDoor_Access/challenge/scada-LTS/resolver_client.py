#!/usr/bin/env python3
import json
import logging
import subprocess
import sys
import time
import socket
from urllib import request, parse, error

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RESOLVER_HOST = "resolver.pccc"
REGISTER_PATH = "/register"
LIST_PATH = "/list"
SLEEP_SECONDS = 5


def post_register(visible_ip: str, reported_ip: str, hostname: str):
    """
    POST to /register with:
      - address: CSV of the two IPs
      - hostname: client hostname (required)
    Returns parsed JSON on success, or None if request failed/JSON invalid.
    """
    url = f"http://{RESOLVER_HOST}{REGISTER_PATH}"
    payload = {
        "address": f"{visible_ip},{reported_ip}",
        "hostname": hostname,
    }
    data = parse.urlencode(payload).encode("utf-8")

    req = request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except error.HTTPError as e:
        logger.warning("HTTP error on /register: %s", e)
    except error.URLError as e:
        logger.warning("URL error on /register: %s", e)
    except json.JSONDecodeError as e:
        logger.warning("Failed to decode JSON from /register: %s", e)

    return None


def get_list():
    """
    GET /list and return (completed, payload).

    completed == True  -> payload is the final list (expected to be a list)
    completed == False -> either HTTP error or JSON that indicates 'incomplete'
    """
    url = f"http://{RESOLVER_HOST}{LIST_PATH}"
    req = request.Request(url, method="GET")

    try:
        with request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body)
    except error.HTTPError as e:
        logger.info("HTTP error on /list (treating as incomplete): %s", e)
        return False, None
    except error.URLError as e:
        logger.info("URL error on /list (treating as incomplete): %s", e)
        return False, None
    except json.JSONDecodeError as e:
        logger.info("Bad JSON from /list (treating as incomplete): %s", e)
        return False, None

    # If resolver returns a dict with a status indicating 'incomplete', keep polling.
    if isinstance(data, dict):
        status = str(data.get("status", "")).lower()
        if status in {"incomplete", "pending"}:
            logger.info("Resolver reports incomplete state: %s", data)
            return False, data

    # Otherwise, assume it's the final list (likely a list of devices).
    return True, {entry["hostname"]: entry for entry in data}

def get_nonlocal_ips():
    """
    Uses `ip -4 -o addr show` to list IPv4 addresses.
    Returns a list of non-local addresses (not 127.x.x.x).
    """
    try:
        output = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"],
            stderr=subprocess.STDOUT
        ).decode().strip()
    except Exception as e:
        logger.error("Failed to run `ip`: %s", e)
        return []

    ips = []
    for line in output.splitlines():
        parts = line.split()
        # ip -4 -o addr output looks like:
        # 2: eth0    inet 10.0.1.10/24 brd ...
        if "inet" in parts:
            idx = parts.index("inet")
            addr = parts[idx + 1]   # e.g. "10.0.1.10/24"
            ip = addr.split("/")[0]
            if not ip.startswith("127."):
                ips.append(ip)

    # Deduplicate while preserving order
    return list(dict.fromkeys(ips))

def register_until_ok(visible_ip: str, reported_ip: str, hostname: str):
    """
    Keep POSTing to /register every SLEEP_SECONDS until we see status=='ok'.
    """
    if not hostname:
        raise ValueError("Hostname must not be empty")

    while True:
        logger.info(
            "Registering with resolver at %s: hostname=%s, visible=%s, reported=%s",
            RESOLVER_HOST,
            hostname,
            visible_ip,
            reported_ip,
        )
        resp = post_register(visible_ip, reported_ip, hostname)
        if isinstance(resp, dict) and resp.get("status") == "ok":
            logger.info("Registration acknowledged by resolver: %s", resp)
            return
        logger.info(
            "Registration not yet acknowledged, retrying in %s seconds",
            SLEEP_SECONDS,
        )
        time.sleep(SLEEP_SECONDS)


def wait_for_complete_list():
    """
    Keep polling /list every SLEEP_SECONDS until resolver returns a completed list.
    Returns that list.
    """
    while True:
        completed, payload = get_list()
        if completed:
            logger.info("Received complete device list from resolver")
            return payload

        logger.info(
            "Device list not complete yet, retrying in %s seconds", SLEEP_SECONDS
        )
        time.sleep(SLEEP_SECONDS)


def main():
    if len(sys.argv) != 3:
        logger.error("Usage: %s <visible_ip> <reported_ip>", sys.argv[0])
        sys.exit(1)

    visible_ip = sys.argv[1]
    reported_ip = sys.argv[2]
    hostname = socket.gethostname().strip()

    if not hostname:
        logger.error("Could not determine hostname, exiting.")
        sys.exit(1)

    logger.info("Local hostname detected as: %s", hostname)

    register_until_ok(visible_ip, reported_ip, hostname)
    devices = wait_for_complete_list()

    logger.info("Final devices list: %s", devices)


if __name__ == "__main__":
    main()
