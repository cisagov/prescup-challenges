import os, re, base64, urllib.request, ssl, hmac, hashlib

def get(url, insecure=False):
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return urllib.request.urlopen(urllib.request.Request(url), context=ctx).read()
    return urllib.request.urlopen(url).read()

# Reconstruct TOKEN3 from comm-intel and compare if operator provided TOKEN3 to this container
mbox = get("http://intel.embassy.svc:8080/mail/ops.mbox").decode(errors="replace")

def parse_real_signed_message(mbox_text: str) -> dict:
    """
    Parse SHARD1/2/3 only from the REAL signed message.
    The real message is identified by X-DI-Mission: T3
    """
    shards = {}
    in_real = False
    in_signed = False

    for line in mbox_text.splitlines():
        line = line.rstrip()

        # Identify the real message block
        if line.startswith("X-DI-Mission: T3"):
            in_real = True

        if not in_real:
            continue

        if line.startswith("BEGIN SIGNED MESSAGE"):
            in_signed = True
            continue

        if line.startswith("END SIGNED MESSAGE"):
            if in_signed:
                break

        if in_signed:
            m = re.match(r"^SHARD([123])=(.+)$", line)
            if m:
                shards[m.group(1)] = m.group(2)

    return shards

shards = parse_real_signed_message(mbox)

missing = [k for k in ["1","2","3"] if k not in shards or not shards[k]]
assert not missing, f"Missing shard(s): {missing}"

# Deterministic shard order
recon = "".join(base64.b64decode(shards[k]).decode("utf-8", errors="strict") for k in ["1","2","3"])

def norm(s: str) -> str:
    # Normalize CRLF and stray whitespace (keeps integrity while avoiding platform newline issues)
    return s.replace("\r\n", "\n").strip()

if os.environ.get("TOKEN3"):
    assert norm(recon) == norm(os.environ["TOKEN3"]), f"TOKEN3 shards mismatch (recon={recon!r})"
else:
    assert len(recon) >= 8, "Reconstructed TOKEN3 looks invalid (too short)"

# Optional HMAC shape test if pepper and tokens provided
pepper = os.environ.get("GRADER_PEPPER")
if pepper:
    for tk in ["TOKEN1","TOKEN2","TOKEN3","TOKEN4","TOKEN5"]:
        if tk in os.environ and os.environ[tk]:
            digest = hmac.new(pepper.encode(), os.environ[tk].encode(), hashlib.sha256).hexdigest()
            assert len(digest) == 64, f"HMAC length bad for {tk}"

print("[diag] functional probe OK")
