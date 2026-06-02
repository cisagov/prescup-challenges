#!/usr/bin/env python3
"""Token 3 — Dead-Drop Enumeration (structured evidence + rate limit).

Awards TOKEN3 when the competitor submits a JSON payload with all four
canonical persistence identifiers (run_key, startup, scheduled_task,
wmi_consumer). Rate-limited to <=5 attempts/minute via a sqlite ledger
at /var/lib/grader/token3-rate.sqlite.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sqlite3
import sys
import time


CANONICAL = {
    "run_key": "SystemServices",
    "startup": "SystemServices.vbs",
    "scheduled_task": r"\Microsoft\Windows\WindowsUpdate\SystemServicesCheck",
    "wmi_consumer": "WindowsHealthMonitor",
}

RATE_LIMIT_DB = pathlib.Path("/var/lib/grader/grader-rate.sqlite")
RATE_BUCKET = "token3"
RATE_WINDOW_S = 60
RATE_LIMIT = 5


def _normalize(value: str) -> str:
    return value.strip().casefold()


def _run_key_matches(submitted: str, expected: str) -> bool:
    # Accept either the bare value name ("SystemServices") or any HKCU/HKLM
    # form ending in "...\Run\SystemServices". Defenders commonly record the
    # full hive path; this normalises both shapes to the leaf value name.
    s = submitted.strip().replace("/", "\\")
    leaf = s.rsplit("\\", 1)[-1]
    return _normalize(leaf) == _normalize(expected)


def _ensure_rate_db() -> sqlite3.Connection:
    RATE_LIMIT_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(RATE_LIMIT_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS attempts (bucket TEXT, source TEXT, ts REAL)")
    conn.execute("CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts(bucket, source, ts)")
    conn.commit()
    return conn


def _rate_limited(conn: sqlite3.Connection, source: str) -> bool:
    now = time.time()
    cutoff = now - RATE_WINDOW_S
    conn.execute("DELETE FROM attempts WHERE ts < ?", (cutoff - 3600,))
    (count,) = conn.execute(
        "SELECT COUNT(*) FROM attempts WHERE bucket = ? AND source = ? AND ts >= ?",
        (RATE_BUCKET, source, cutoff),
    ).fetchone()
    return count >= RATE_LIMIT


def _record(conn: sqlite3.Connection, source: str) -> None:
    conn.execute(
        "INSERT INTO attempts(bucket, source, ts) VALUES (?, ?, ?)",
        (RATE_BUCKET, source, time.time()),
    )
    conn.commit()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="")
    parser.add_argument(
        "--source",
        default=os.environ.get("GRADER_REMOTE_ADDR", "unknown"),
        help="Submission source identifier for rate-limit bucketing",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)
    log = logging.getLogger("token3")

    conn = _ensure_rate_db()
    if _rate_limited(conn, args.source):
        log.info("Token 3 source %s rate-limited", args.source)
        print(
            "deadDropEnumeration: Failure - \u274c rate limit exceeded; "
            f"wait {RATE_WINDOW_S}s and retry"
        )
        return 0
    _record(conn, args.source)

    try:
        payload = json.loads(args.input) if args.input else {}
    except json.JSONDecodeError:
        log.info("Token 3 submission was not valid JSON")
        print("deadDropEnumeration: Failure - \u274c submit JSON with the four mechanism keys")
        return 0

    if not isinstance(payload, dict):
        print("deadDropEnumeration: Failure - \u274c submit JSON object with the four mechanism keys")
        return 0

    missing = [k for k in CANONICAL if k not in payload or not str(payload[k]).strip()]
    if missing:
        log.info("Token 3 submission missing keys: %s", missing)
        print("deadDropEnumeration: Failure - \u274c incomplete evidence set")
        return 0

    mismatches: list[str] = []
    for key, expected in CANONICAL.items():
        raw = str(payload[key])
        if key == "run_key":
            ok = _run_key_matches(raw, expected)
        else:
            ok = _normalize(raw) == _normalize(expected)
        if not ok:
            mismatches.append(key)

    if mismatches:
        log.info("Token 3 mismatched fields: %s", mismatches)
        print("deadDropEnumeration: Failure - \u274c one or more identifiers do not match the host evidence")
        return 0

    log.info("Token 3 full canonical set verified")
    print("deadDropEnumeration: Success - \u2705 all four persistence mechanisms confirmed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
