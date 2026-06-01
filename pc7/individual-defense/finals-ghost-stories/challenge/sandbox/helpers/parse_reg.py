#!/usr/bin/env python3
"""Quickstart for parsing Windows `.reg` text exports.

`.reg` files are the human-readable export format produced by
`reg export`. This helper enumerates every `[key]` block and prints the
value names + data under each, so you can search programmatically
instead of opening a text editor.

Example:
    python3 parse_reg.py /path/to/NTUSER.DAT.reg
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


KEY_RE = re.compile(r"^\[(.+?)\]\s*$")
VALUE_RE = re.compile(r'^"(?P<name>(?:[^"\\]|\\.)*)"=(?P<rest>.*)$')


def parse(reg_path: Path) -> list[tuple[str, list[tuple[str, str]]]]:
    """Return [(key, [(name, rawvalue), ...]), ...]."""
    text = reg_path.read_text(encoding="utf-16" if reg_path.read_bytes()[:2] == b"\xff\xfe" else "utf-8", errors="replace")
    result: list[tuple[str, list[tuple[str, str]]]] = []
    current_key: str | None = None
    current_values: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith(";"):
            continue
        m = KEY_RE.match(line)
        if m:
            if current_key is not None:
                result.append((current_key, current_values))
            current_key = m.group(1)
            current_values = []
            continue
        m = VALUE_RE.match(line)
        if m and current_key is not None:
            name = m.group("name").replace('\\"', '"').replace("\\\\", "\\")
            current_values.append((name, m.group("rest")))
    if current_key is not None:
        result.append((current_key, current_values))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reg_file", type=Path)
    parser.add_argument("--filter", help="Substring match on key name (case-insensitive)")
    args = parser.parse_args()

    for key, values in parse(args.reg_file):
        if args.filter and args.filter.casefold() not in key.casefold():
            continue
        print(f"[{key}]")
        if not values:
            print("  <no values>")
        for name, raw in values:
            print(f"  {name!r:40s} = {raw}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
