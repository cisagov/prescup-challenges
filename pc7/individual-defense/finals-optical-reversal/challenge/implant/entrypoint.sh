#!/usr/bin/env bash
set -euo pipefail

export TOKEN1 TOKEN2 TOKEN3 TOKEN4 TOKEN5 TOKEN6 TOKEN7
export LINK_CODE DIFFICULTY HINT_LEVEL NONCE_TTL_SECONDS
export BEACON_HOST BEACON_PORT BEACON_INTERVAL BEACON_DOMAIN
export CLIENT_IDLE_TIMEOUT LOG_LEVEL

mkdir -p /dev/shm/optic /opt/clues /opt/specs /opt/artifacts /opt/implant

python3 - <<'PY'
import os
import subprocess
import hashlib
import ipaddress
from pathlib import Path

art = Path("/opt/artifacts")
art.mkdir(parents=True, exist_ok=True)

def get_eth0_ipv4() -> str:
    """
    Deterministically select the implant's challenge-network IPv4 from eth0.
    This avoids hostname -I ordering issues when multiple private interfaces exist.
    """
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", "eth0"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("inet "):
                continue
            cidr = line.split()[1]          # e.g. 10.0.21.2/26
            ip = cidr.split("/")[0]
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4 and ip_obj.is_private and not ip_obj.is_loopback:
                return ip
    except Exception:
        pass

    return "127.0.0.1"

ipv4 = os.getenv("IMPLANT_IP", get_eth0_ipv4())

def rc4_key_schedule(key: bytes):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s

def rc4_crypt(data: bytes, key: bytes):
    s = rc4_key_schedule(key)
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out.append(byte ^ k)
    return bytes(out)

t4 = os.getenv("TOKEN4", "PCCC{t4_missing}").encode()
k4 = hashlib.sha1(("opr:" + ipv4).encode()).digest()[:16]
(art / "t4.rc4").write_bytes(rc4_crypt(t4, k4))

state = 0xA7
def lfsr_next():
    global state
    out = 0
    for i in range(8):
        bit = state & 1
        out |= (bit << i)
        newbit = 0
        if state & 1:
            newbit ^= 1
        if state & 2:
            newbit ^= 1
        if state & 4:
            newbit ^= 1
        if state & 8:
            newbit ^= 1
        state = ((state >> 1) | (newbit << 7)) & 0xFF
    return out

t5 = os.getenv("TOKEN5", "PCCC{t5_missing}").encode()
keystream = bytes(lfsr_next() for _ in range(len(t5)))
scrambled = bytes(a ^ b for a, b in zip(t5, keystream))
(art / "t5.lfsr").write_bytes(scrambled)
PY

LD_PRELOAD=/opt/optic/bin/libldshim.so IMPLANT_PORT=31337 SPEC_PORT=30415 /opt/optic/bin/agent_daemon &

python3 -m http.server 8080 --directory /opt/www >/dev/null 2>&1 &

exec python3 /opt/implant/server.py