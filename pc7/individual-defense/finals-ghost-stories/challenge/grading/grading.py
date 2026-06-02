#!/usr/bin/env python3
"""Grading driver for Operation Ghost Stories.

The prescup-challenge-server invokes this script in `text` grading mode
once per submission with one positional argument per text box, in the
order parts are listed in grader_config.yml:

    sys.argv[1] -> assetIdentification text-box input  (Token 1)
    sys.argv[2] -> defensiveEvasion    text-box input  (Token 2)
    sys.argv[3] -> deadDropEnumeration text-box input  (Token 3)
    sys.argv[4] -> handlersInstructions text-box input (Token 4)

This driver dispatches each argument to its per-token grading script,
collects the resulting `<check_key>: <Success/Failure - msg>` line, and
emits all four on its own stdout — the prescup server parses every
matching line as a grading result. All diagnostics go to stderr per
docs/challenge-standards.md §10.2.

A solved-state file at /var/lib/grader/solved.json tracks which parts
have already been awarded. If a part is already solved and the current
submission is empty, the driver re-emits Success so the challenge server
doesn't overwrite a previously-awarded token.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path("/custom_scripts")
SOLVED_FILE = Path("/var/lib/grader/solved.json")

# Order MUST match the order of parts in grader_config.yml.
PART_ORDER: list[tuple[str, str]] = [
    ("assetIdentification",  "grade_token1.py"),
    ("defensiveEvasion",     "grade_token2.py"),
    ("deadDropEnumeration",  "grade_token3.py"),
    ("handlersInstructions", "grade_token4.py"),
]

# Parts that need to know the submission source (for rate-limit bucketing).
SOURCE_AWARE = {"defensiveEvasion", "deadDropEnumeration"}

# Success messages to re-emit for already-solved parts.
SOLVED_MESSAGES: dict[str, str] = {
    "assetIdentification":  "\u2705 dropper SHA256 verified",
    "defensiveEvasion":     "\u2705 canonical evasion command verified",
    "deadDropEnumeration":  "\u2705 all four persistence mechanisms confirmed",
    "handlersInstructions": "\u2705 decoded payload SHA256 verified",
}


def _load_solved() -> set[str]:
    if SOLVED_FILE.is_file():
        try:
            return set(json.loads(SOLVED_FILE.read_text()))
        except (json.JSONDecodeError, TypeError):
            pass
    return set()


def _mark_solved(part: str) -> None:
    solved = _load_solved()
    solved.add(part)
    SOLVED_FILE.parent.mkdir(parents=True, exist_ok=True)
    SOLVED_FILE.write_text(json.dumps(sorted(solved)))


def _run_grader(part: str, script: str, value: str, source: str) -> str:
    """Run one per-token grading script and return its grading-result line."""
    log = logging.getLogger("grading.dispatch")
    cmd = [sys.executable, str(SCRIPTS_DIR / script), "--input", value]
    if part in SOURCE_AWARE:
        cmd.extend(["--source", source])
    log.info("part=%s script=%s", part, script)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
    except subprocess.TimeoutExpired:
        log.error("part=%s timed out", part)
        return f"{part}: Failure - grading script timed out"

    if result.stderr:
        for line in result.stderr.splitlines():
            log.info("[%s/stderr] %s", part, line)

    for line in result.stdout.splitlines():
        if line.startswith(f"{part}:"):
            return line
    log.error("part=%s produced no result line; stdout=%r", part, result.stdout)
    return f"{part}: Failure - grading script produced no result"


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr)
    log = logging.getLogger("grading")

    submissions = sys.argv[1:]
    source = os.environ.get("GRADER_REMOTE_ADDR", "unknown")
    solved = _load_solved()

    if len(submissions) < len(PART_ORDER):
        submissions = list(submissions) + [""] * (len(PART_ORDER) - len(submissions))
    elif len(submissions) > len(PART_ORDER):
        log.warning("received %d args, expected %d; ignoring extras", len(submissions), len(PART_ORDER))
        submissions = submissions[: len(PART_ORDER)]

    for (part, script), value in zip(PART_ORDER, submissions):
        # If already solved and no new submission, re-emit Success.
        if part in solved and not value.strip():
            msg = SOLVED_MESSAGES.get(part, "already solved")
            log.info("part=%s already solved, re-emitting Success", part)
            print(f"{part}: Success - {msg}")
            continue

        result_line = _run_grader(part, script, value, source)

        # Track newly solved parts.
        if ": Success" in result_line:
            _mark_solved(part)

        print(result_line)

    return 0


if __name__ == "__main__":
    sys.exit(main())
