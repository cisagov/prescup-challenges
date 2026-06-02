#!/usr/bin/env python3
"""Token 2 — Defensive Evasion.

Awards TOKEN2 when the competitor submits the canonical PowerShell
command the asset used to suppress monitoring before deploying the
implant. Accepted forms (all case-insensitive, whitespace-normalized):
  - Set-MpPreference -DisableRealtimeMonitoring $true
  - Set-MpPreference -DisableRealtimeMonitoring 1
  - Set-MpPreference -DisableRealtimeMonitoring true

The grader requires the full `Set-MpPreference` prefix so the competitor
must have actually found the script-block event in the PowerShell EVTX
data; the bare parameter name is not accepted.

Rate-limited to 5 attempts/minute/source via the same sqlite ledger
used by Token 3 (`/var/lib/grader/grader-rate.sqlite`).
"""
from __future__ import annotations

import argparse
import logging
import os
import pathlib
import re
import sqlite3
import sys
import time


# Single canonical command, three accepted boolean forms.
ACCEPTED = {
    "set-mppreference -disablerealtimemonitoring $true",
    "set-mppreference -disablerealtimemonitoring 1",
    "set-mppreference -disablerealtimemonitoring true",
}

RATE_LIMIT_DB = pathlib.Path("/var/lib/grader/grader-rate.sqlite")
RATE_BUCKET = "token2"
RATE_WINDOW_S = 60
RATE_LIMIT = 5


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


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
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)
    log = logging.getLogger("token2")

    conn = _ensure_rate_db()
    if _rate_limited(conn, args.source):
        log.info("Token 2 source %s rate-limited", args.source)
        print(f"defensiveEvasion: Failure - \u274c rate limit exceeded; wait {RATE_WINDOW_S}s and retry")
        return 0
    _record(conn, args.source)

    submitted = _normalize(args.input)
    if not submitted:
        print("defensiveEvasion: Failure - \u274c submission empty")
        return 0

    if submitted in ACCEPTED:
        log.info("Token 2 canonical form accepted")
        print("defensiveEvasion: Success - \u2705 canonical evasion command verified")
        return 0

    log.info("Token 2 submission %r did not match canonical form", submitted)
    print("defensiveEvasion: Failure - \u274c submission does not match the command recorded in the host's PowerShell operational log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
