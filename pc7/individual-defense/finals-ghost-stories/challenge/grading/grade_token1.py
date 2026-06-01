#!/usr/bin/env python3
"""Token 1 — Asset Identification.

Awards TOKEN1 when the competitor submits the SHA256 of install_obf.bat.
The expected hash is staged at /hosted_files/.expected/install_obf.bat.sha256
when the grader image is built.
"""
from __future__ import annotations

import argparse
import logging
import pathlib
import re
import sys


EXPECTED_HASH_FILE = pathlib.Path("/opt/grader-private/expected/install_obf.bat.sha256")
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _normalize(value: str) -> str:
    # Accept "sha256=<hex>", "SHA256: <hex>", whitespace, mixed case.
    cleaned = value.strip()
    for prefix in ("sha256=", "SHA256=", "sha256:", "SHA256:"):
        if cleaned.lower().startswith(prefix.lower()):
            cleaned = cleaned[len(prefix):].strip()
    return cleaned.split()[0] if cleaned else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)
    log = logging.getLogger("token1")

    if not EXPECTED_HASH_FILE.is_file():
        log.error("expected hash file missing: %s", EXPECTED_HASH_FILE)
        print("assetIdentification: Failure - \u274c grader misconfigured (expected hash missing)")
        return 0

    expected = EXPECTED_HASH_FILE.read_text().strip().lower()
    submitted = _normalize(args.input).lower()

    if not _HEX64.match(submitted):
        log.info("Token 1 submission not a valid SHA256")
        print("assetIdentification: Failure - \u274c submit a 64-char hex SHA256")
        return 0

    if submitted == expected:
        log.info("Token 1 hash matched")
        print("assetIdentification: Success - \u2705 dropper SHA256 verified")
    else:
        log.info("Token 1 hash mismatch")
        print("assetIdentification: Failure - \u274c hash does not match the recovered dropper")
    return 0


if __name__ == "__main__":
    sys.exit(main())
