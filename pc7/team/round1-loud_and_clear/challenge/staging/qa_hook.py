#!/usr/bin/env python3
import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Dict, Optional

STATE_DIR = Path("/opt/lancer/state")
TOK_DIR = Path("/opt/lancer/tokens")
PATCH_FILE = STATE_DIR / "patch_level"
STAGE_FILE = STATE_DIR / "staged_payload.sh"

SPOOL_DIR = Path("/var/spool/exim4/input")

# Header used for patches 1-4
QA_HEADER = "x-lancer-qa"
# Header used for patch 5 staging
HEX_HEADER = "x-lancer-payload"

def read_patch() -> int:
    try:
        n = int(PATCH_FILE.read_text().strip())
        return n if 1 <= n <= 5 else 1
    except Exception:
        return 1

def token_value(n: int) -> str:
    p = TOK_DIR / f"token{n}.txt"
    if not p.exists():
        return ""
    return p.read_text(errors="replace").strip()

def read_headers_from_spool(message_id: str, max_bytes: int = 256_000) -> Dict[str, str]:
    """
    Parse message headers from the Exim data spool file (<id>-D).
    We only need a few headers; keep parsing simple & robust.
    """
    dfile = SPOOL_DIR / f"{message_id}-D"
    if not dfile.exists():
        return {}

    raw = dfile.read_bytes()[:max_bytes]
    # Exim spool stores the RFC822 message with CRLF. Decode safely.
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()

    headers: Dict[str, str] = {}
    cur: Optional[str] = None
    for line in lines:
        if line == "":
            break
        if line.startswith((" ", "\t")) and cur is not None:
            headers[cur] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        cur = k.strip().lower()
        headers[cur] = v.strip()
    return headers

def one_line(s: str, max_len: int = 180) -> str:
    s = s.replace("\r", " ").replace("\n", " ").strip()
    if len(s) > max_len:
        s = s[:max_len] + "…"
    # SMTP replies cannot contain control chars
    s = re.sub(r"[\x00-\x1f\x7f]+", "", s)
    return s

def extract_expected(output: str, expected: str) -> Optional[str]:
    if expected and expected in output:
        return expected
    return None

def sh(cmd: str, timeout: int = 2) -> str:
    # Limit execution time and output size.
    proc = subprocess.run(
        ["/bin/sh", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    out = proc.stdout or ""
    if len(out) > 4096:
        out = out[:4096]
    return out

def exim_expand(s: str, timeout: int = 2) -> str:
    proc = subprocess.run(
        ["/usr/sbin/exim4", "-be", s],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    out = proc.stdout or ""
    if len(out) > 4096:
        out = out[:4096]
    return out

def patch1(payload: str) -> str:
    # Vulnerable: raw interpolation into a shell command (no quoting).
    out = sh(f"echo {payload}")
    expected = token_value(1)
    hit = extract_expected(out, expected)
    return hit or "QA: no signal (patch 1)"

def patch2(payload: str) -> str:
    # 'Fixed': strip some separators, then double-quote. Still vulnerable to $() substitution.
    filtered = re.sub(r"[;&|]", "", payload)
    # Intentionally (incorrectly) leave $() intact.
    out = sh(f'echo "{filtered}"')
    expected = token_value(2)
    hit = extract_expected(out, expected)
    return hit or "QA: rejected (patch 2)"

def patch3(payload: str) -> str:
    # 'Fixed again': try to kill $() by stripping $, (, ). Regression: forgot backticks.
    filtered = re.sub(r"[;&|$()]", "", payload)
    out = sh(f'echo "{filtered}"')
    expected = token_value(3)
    hit = extract_expected(out, expected)
    return hit or "QA: sanitized (patch 3)"

def patch4(payload: str) -> str:
    # Migrated to Exim macro expansion for templating.
    # Blacklist-based guard that blocks obvious RCE primitives, but still permits file reads.
    lower = payload.lower()
    if "${run" in lower or "${perl" in lower or "${exec" in lower:
        return "QA: macro denied (patch 4)"
    out = exim_expand(payload)
    expected = token_value(4)
    hit = extract_expected(out, expected)
    return hit or "QA: macro ok (patch 4)"

def main():
    patch = read_patch()

    # Patches 1-4 keep the ORIGINAL convention:
    #   qa_hook.py audit <message_id>
    if len(sys.argv) != 3:
        print("QA: usage error")
        return

    action = sys.argv[1].lower()
    message_id = sys.argv[2].strip()

    if action != "audit":
        print(f"QA: wrong action for patch {patch}")
        return

    headers = read_headers_from_spool(message_id)
    payload = headers.get(QA_HEADER, "")
    if not payload:
        print(f"QA: missing X-Lancer-QA (patch {patch})")
        return

    payload = payload.replace("\r", " ").replace("\n", " ")

    if patch == 1:
        out = patch1(payload)
    elif patch == 2:
        out = patch2(payload)
    elif patch == 3:
        out = patch3(payload)
    elif patch == 4:
        out = patch4(payload)
    else:
        out = "QA: invalid patch state"

    print(one_line(out))

if __name__ == "__main__":
    main()
