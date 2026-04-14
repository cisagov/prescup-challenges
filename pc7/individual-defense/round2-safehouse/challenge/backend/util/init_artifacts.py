import hashlib, os, base64, pathlib, textwrap, zipfile, subprocess, secrets
from urllib.parse import quote_plus

_RUN_SEED = secrets.token_bytes(2)
ART_DIR = pathlib.Path("/app/artifacts")
ART_DIR.mkdir(parents=True, exist_ok=True)

def _token(name: str, default: str) -> str:
    return os.getenv(name, default).strip()

def _write(path: pathlib.Path, data: bytes):
    path.write_bytes(data)

def _make_web_access_log():
    """Token 2: exfil payload in access log query (base64), blended into realistic noise."""
    import random
    from hashlib import sha256
    from datetime import datetime, timedelta

    token2 = _token("TOKEN2", "PCCC{contact-support-token2}")
    b64 = base64.b64encode(token2.encode()).decode()
    rb64 = b64[::-1]
    rb64_enc = quote_plus(rb64)

    dd_pw = _token("DEAD_DROP_PW", "FIELD-SEAL-7Z")
    dd_b64 = base64.b64encode(dd_pw.encode()).decode()[::-1]
    dd_b64_enc = quote_plus(dd_b64)

    # 🔴 Custom / anomalous User-Agent (the investigative signal)
    ua_custom = '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36; SecureOS; rv:91.3)"'

    # Normal background User-Agents
    ua_pool = [
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"',
        '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"',
        '"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/118.0"',
        '"curl/7.68.0"',
        '"Go-http-client/1.1"',
        '"kube-probe/1.26"',
        '"ELB-HealthChecker/2.0"',
        '"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
    ]

    # Deterministic RNG so layout is stable per TOKEN2
    random.seed(sha256(token2.encode()).digest())

    lines = []

    # --- Generate realistic noise ---
    base_time = datetime(2025, 8, 21, 0, 0, 0)
    for _ in range(5000):
        ts = base_time + timedelta(seconds=random.randint(0, 86400))
        ip = f"10.0.{random.randint(1,5)}.{random.randint(2,254)}"
        path = random.choice([
            "/", "/status", "/login", "/assets/app.js",
            "/docs/sop-legacy.pdf", "/api/health",
            "/favicon.ico"
        ])
        status = random.choice([200, 200, 200, 304, 404, 500])
        size = random.randint(20, 8000)
        ua = random.choice(ua_pool)

        lines.append(
            f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {path} HTTP/1.1" {status} {size} "-" {ua}'
        )

    # --- Original legacy lines (UNCHANGED semantics, new UA only) ---
    legacy_lines = []

    legacy_lines.append(
        '10.0.3.21 - - [21/Aug/2025:03:10:11 +0000] '
        '"GET /status HTTP/1.1" 200 42 "-" ' + ua_custom
    )

    legacy_lines.append(
        f'172.18.0.9 - legacy [21/Aug/2025:03:44:44 +0000] '
        f'"GET /legacy-intake?stage=1&callback={rb64_enc} HTTP/1.1" 404 0 "-" {ua_custom}'
    )

    legacy_lines.append(
        f'172.18.0.9 - legacy [21/Aug/2025:03:45:12 +0000] '
        f'"GET /legacy-intake?stage=2&ddpw={dd_b64_enc} HTTP/1.1" 404 0 "-" {ua_custom}'
    )

    legacy_lines.append(
        '10.0.3.21 - - [21/Aug/2025:03:45:59 +0000] '
        '"GET /docs/sop-legacy.pdf HTTP/1.1" 200 1204 "-" ' + ua_custom
    )

    # Insert legacy lines at deterministic position
    insert_at = int(sha256(token2.encode()).hexdigest(), 16) % len(lines)
    for i, ll in enumerate(legacy_lines):
        lines.insert(insert_at + i, ll)

    _write(ART_DIR / "web_access.log", ("\n".join(lines) + "\n").encode())

def _make_opsec_fieldcard():
    """
    Non-token artifact: a subtle nudge that the *archive metadata* matters.
    This is intentionally short/vague (Round 2).
    """
    card = textwrap.dedent("""\
        SAFEHOUSE // OPSEC FIELD CARD // DEAD DROP RECOVERY TTPS

        - When operational, trust your gut.
        - Archives have *metadata* (comments) that survive encryption.
        - If you find ciphertext in an archive comment, remember: the XOR key is usually hidden in *another* comment.

    """)
    _write(ART_DIR / "opsec_fieldcard.txt", card.encode())


def _xor(data: bytes, key: int) -> bytes:
    return bytes([b ^ (key & 0xFF) for b in data])


def _zip_with_comments(tmp_zip: pathlib.Path, *, archive_comment: bytes, file_comment: bytes):
    """
    Build an unencrypted ZIP with:
      - archive comment (EOCD comment)
      - per-file comment on ops_memo.txt (central-directory comment)
    We'll then encrypt entries with zipcloak to force challengers away from content-based extraction.
    """
    with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # ops memo: intentionally generic / decoy-ish
        zi = zipfile.ZipInfo("ops_memo.txt")
        zi.compress_type = zipfile.ZIP_DEFLATED
        # zipfile supports per-file comments (central directory)
        zi.comment = file_comment[:0xFFFF]
        zf.writestr(
            zi,
            textwrap.dedent("""\
                OPS MEMO // INTERNAL
                - Drop packaging updated.
                - Contents are expendable.
                - Verify archive metadata before trusting payloads.
            """),
        )

        # payload: pure decoy noise
        zf.writestr("payload.bin", secrets.token_bytes(256))

        # archive (EOCD) comment
        zf.comment = archive_comment[:0xFFFF]


def _encrypt_zip_in_place(zip_path: pathlib.Path, password: str):
    """
    Encrypt entries without touching archive/file comments.
    Uses ZipCrypto via `zipcloak` (available when `zip` package installed).
    """
    # zipcloak rewrites in-place by default; -P for non-interactive password
    result = subprocess.run(
        ["zipcloak", "-P", password, str(zip_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # zipcloak exit code 16 = "nothing to do" (already encrypted / no eligible entries)
    if result.returncode not in (0, 16):
        raise subprocess.CalledProcessError(
            result.returncode, result.args
        )


def _make_dead_drops():
    """
    Token 3 (Upgraded):
      - 10 dead_drops, same structure, only one yields the real token.
      - Archive comment holds XOR-encrypted bytes (NOT stringable).
      - Per-file comment on ops_memo.txt provides the XOR key hint.
      - ZIP entries are password-protected to prevent content-based shortcuts.
    """
    token3 = _token("TOKEN3", "PCCC{demo-token3}")

    # Password: keep deterministic (no brute force), but discoverable elsewhere.
    # You can later tie this to an existing intel artifact; for now it's provided via env with a safe default.
    dd_pw = _token("DEAD_DROP_PW", "FIELD-SEAL-7Z")

    # 1 real + 9 fake. Fake outputs are operation names in various wrappers.
    operations = [
        ("[[OPERATION_COLD_ANVIL]]", 0x41),
        ("//OPERATION_SILENT_WATCH//", 0x52),
        ("/OPERATION_DEAD_LEAF/", 0x33),
        ("<OPERATION_IRON_VEIL>", 0x27),
        ("{OPERATION_NIGHT_FERRY}", 0x6D),
        ("OPERATION_STONE_GAZE", 0x19),
        ("TOKEN=OPERATION_FOG_HARBOR", 0x7B),
        ("(OPERATION_GLASS_RIVER)", 0x2E),
        ("{OPERATION_BLACK_TIDE}", 0x5F),  # one "almost token" trap
    ]

    # Choose which index is real in a deterministic way based on token3 (no RNG surprises)
    # This prevents challengers from using "first file" heuristics across runs.
    
    # Legacy check
    # h = int.from_bytes(__import__("hashlib").sha256(token3.encode()).digest()[:2], "big")
    # real_idx = h % 10  # 0..9


    # Randomize check
    h = hashlib.sha256(
        token3.encode() + _RUN_SEED
    ).digest()

    real_idx = int.from_bytes(h[:2], "big") % 10


    # Build 10 zips
    for i in range(1, 11):
        idx = i - 1
        name = f"dead_drop_{i:02d}.zip"
        out_zip = ART_DIR / name
        tmp_zip = ART_DIR / (name + ".tmp")

        # XOR key stored in file comment in a compact way.
        # Use different keys across drops to punish copy/paste tooling.
        if idx == real_idx:
            key = (0xA0 ^ h[0]) & 0xFF
            # plaintext is HEX of the token bytes, prefixed (so they must parse and decode)
            plain = b"T3:" + __import__("binascii").hexlify(token3.encode())
        else:
            op_text, k = operations[(idx - (1 if idx > real_idx else 0)) % len(operations)]
            key = k & 0xFF
            # plain is operation marker + operation string (no token substring)
            # masquerading as real token
            plain = ("OP:" + op_text).encode()

        # Encrypt plaintext and store as *binary* in archive comment with a small header.
        cipher = _xor(plain, key)
        # Header is printable, rest is binary; forces xxd/byte handling but still discoverable.
        archive_comment = b"SAFEHOUSE_DD3\x00" + cipher

        # File comment: key hint, but not spelled out like a tutorial.
        # Keep it short and slightly oblique for Round 2.
        file_comment = f"cmt-k:{key:02x}".encode()

        _zip_with_comments(tmp_zip, archive_comment=archive_comment, file_comment=file_comment)

        # Encrypt the entries so they can't just unzip and read strings from files.
        tmp_zip.replace(out_zip)  # move into place
        _encrypt_zip_in_place(out_zip, dd_pw)

        # Clean up any leftover
        if tmp_zip.exists():
            tmp_zip.unlink()


# def _make_zip_dead_drop():
#    """
#    Back-compat: keep a single name for older docs/UI, but point it to dead_drop_01.zip.
#    (The real token is NOT guaranteed to be in _01; challengers must validate.)
#    """
#    # Provide a stable "landing" artifact for players who don't enumerate lists.
#    # We'll just copy dead_drop_01.zip after generation.
#    dd1 = ART_DIR / "dead_drop_01.zip"
#    if dd1.exists():
#        _write(ART_DIR / "dead_drop.zip", dd1.read_bytes())


def _bundle_dead_drops():
    """
    Bundle all dead_drop_XX.zip files into a single dead_drop.zip.
    The outer archive is NOT encrypted.
    """
    bundle = ART_DIR / "dead_drop.zip"

    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(1, 11):
            name = f"dead_drop_{i:02d}.zip"
            path = ART_DIR / name
            if path.exists():
                zf.write(path, arcname=name)

def _make_mem_strings():
    """Token 4: token XOR’d with key 0x23, hidden in binary section with locator hint."""
    import os
    token4 = os.getenv("TOKEN4", "TOKEN4{demo-token4}")
    key = 0x23
    xored = bytes([b ^ key for b in token4.encode()])

    # Initial "strings"-like lines without locator (we'll add it once we know offset)
    base_lines = [
        "libssl.so.3",
        "pthread_cond_wait",
        "TLSv1.3",
        "kworker/0:1",
        "systemd-udevd",
        "end_of_capture",
    ]

    # Build preliminary ASCII block to measure its length
    ascii_block = "\n".join(base_lines).encode("utf-8") + b"\n"
    base_len = len(ascii_block)

    # Choose the next 0x10 boundary after the ASCII block as the binary insertion point
    offset = ((base_len // 0x10) + 1) * 0x10

    # Now rebuild with a proper locator line
    lines = [
        "libssl.so.3",
        "pthread_cond_wait",
        "TLSv1.3",
        "kworker/0:1",
        "systemd-udevd",
        f"LOCATOR: offset=0x{offset:x} size={len(xored)}",
        "end_of_capture",
    ]
    ascii_block = "\n".join(lines).encode("utf-8") + b"\n"

    # Pad to the computed offset
    buf = ascii_block
    if len(buf) < offset:
        buf += b"\x00" * (offset - len(buf))

    # Insert the hidden XOR'd bytes
    buf += xored

    # Add noise after the payload
    buf += os.urandom(64)

    # Write to artifacts
    (ART_DIR / "mem.strings").write_bytes(buf)

def ensure_artifacts():
    _make_web_access_log()
    _make_opsec_fieldcard()
    _make_dead_drops()
    _bundle_dead_drops()
    _make_mem_strings()
