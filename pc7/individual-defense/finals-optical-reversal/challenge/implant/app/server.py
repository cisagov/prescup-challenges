#!/usr/bin/env python3
import base64
import fcntl
import hashlib
import hmac
import ipaddress
import logging
import os
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("null-horizon")

BANNER = """\
🧠 NULL-HORIZON Neural Implant Link (v1.02 r2262)
🟢️ You are connected to the implant’s optical link bus.

Type 'help' for commands. Start with 'handshake'.
"""

HELP = """\
Commands:
  help                          Show this help.
  about                         Print storyline.
  handshake <hex>               Complete link-layer handshake (see UDP spec on port 30415).
  download <frames|rc4|lfsr>    Download artifacts for TOKEN2, TOKEN4, and TOKEN5.
  frames submit <plaintext>     Submit decoded control frames to retrieve TOKEN2.
  beacon submit <plaintext>     Submit token recovered from DNS beacon (TOKEN3).
  rc4 submit <plaintext>        Submit plaintext recovered from RC4 file (TOKEN4).
  lfsr submit <plaintext>       Submit plaintext recovered from LFSR file (TOKEN5).
  pulse start                   Begin timing channel (TOKEN6).
  pulse tick                    Emit one pulse (observe round-trip timing).
  pulse stop                    Stop timing channel.
  pulse submit <plaintext>      Submit TOKEN6 plaintext recovered from timing.
  finalize <hmac8>              Complete final HMAC with NONCE to reveal TOKEN7.
  tokens                        Show tokens you have recovered so far.
  quit
"""

ABOUT = """\
Blacklight recovered a neural optic implant from a covert cell. It lies when
observed at high levels. Only low-level, observer-safe methods work reliably:
syscalls, raw packet capture, process memory, and careful protocol work.

Your mission: recover seven tokens by completing a link handshake (1), frame
decoding (2), DNS beacon capture (3), and three new channels:
- RC4 artifact (4)
- LFSR scrambler (5)
- Timing channel (6)
Then finalize with an HMAC gate (7). The spec is on UDP 30415 (send 'SPEC').
"""

TOKENS = {
    "TOKEN1": os.getenv("TOKEN1", "PCCC{Contact_Support_01}"),
    "TOKEN2": os.getenv("TOKEN2", "PCCC{Contact_Support_02}"),
    "TOKEN3": os.getenv("TOKEN3", "PCCC{Contact_Support_03}"),
    "TOKEN4": os.getenv("TOKEN4", "PCCC{Contact_Support_04}"),
    "TOKEN5": os.getenv("TOKEN5", "PCCC{Contact_Support_05}"),
    "TOKEN6": os.getenv("TOKEN6", "PCCC{Contact_Support_06}"),
    "TOKEN7": os.getenv("TOKEN7", "PCCC{Contact_Support_07}"),
}

DIFFICULTY = int(os.getenv("DIFFICULTY", "3"))
HINT_LEVEL = int(os.getenv("HINT_LEVEL", "0"))
LINK_CODE = os.getenv("LINK_CODE", "LINK_OPEN_SESAME_997414")

TCP_PORT = int(os.getenv("IMPLANT_PORT", "31337"))
UDP_PORT = int(os.getenv("SPEC_PORT", "30415"))
CLIENT_IDLE_TIMEOUT = int(os.getenv("CLIENT_IDLE_TIMEOUT", "1800"))

NONCE_PATH = Path("/opt/implant/nonce.txt")
FINAL_OK_PATH = Path("/opt/implant/final.ok")
DNS_TOKEN_PATH = Path("/dev/shm/dns_token.txt")
SPEC_PATH = Path("/opt/specs/optical_link_v1.md")

BEACON_HOST = os.getenv("BEACON_HOST", "challenge.pccc")
BEACON_PORT = int(os.getenv("BEACON_PORT", "53"))
BEACON_INTERVAL = float(os.getenv("BEACON_INTERVAL", "5"))
BEACON_DOMAIN = os.getenv("BEACON_DOMAIN", "telemetry.null-horizon.local")

STATE = {
    "handshaked": False,
    "frames_ok": False,
    "rc4_ok": False,
    "lfsr_ok": False,
    "pulse_active": False,
    "pulse_ok": False,
    "pulse_index": 0,
    "dns_ok": False,
    "downloads": {
        "rc4": "/opt/artifacts/t4.rc4",
        "lfsr": "/opt/artifacts/t5.lfsr",
    },
}


def fair_hint(msg: str) -> str:
    if HINT_LEVEL >= 2 or (HINT_LEVEL == 1 and DIFFICULTY <= 2):
        return f"[hint] {msg}\n"
    return ""


def atomic_write_text(path: Path, value: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(value)
    os.replace(tmp, path)


def read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text().strip()
    except Exception:
        return default


def compute_expected_handshake(sockaddr):
    ip = sockaddr[0]
    try:
        ip_bytes = socket.inet_aton(ip)
    except OSError:
        ip_bytes = socket.inet_aton("127.0.0.1")
    k = bytearray(hashlib.md5(ip_bytes).digest()[:4])
    for i in range(4):
        k[i] ^= 0x5A
    msg = bytearray(b"OPTO")
    for i in range(4):
        msg[i] ^= k[i]
    return msg.hex()


def encode_frames(plaintext: str, hostname: str = "null-horizon.local") -> str:
    ip_str = socket.gethostbyname(hostname)
    ip_bytes = socket.inet_aton(ip_str)
    base = (sum(ip_bytes) ^ 0xA5) & 0xFF

    pt = plaintext.encode("utf-8")
    out = bytearray()
    for i, b in enumerate(pt):
        key = (base + i) & 0xFF
        out.append(b ^ key)

    return out.hex()


def check_frames(plaintext: str) -> bool:
    target = LINK_CODE
    pt = plaintext.strip()

    if DIFFICULTY == 3:
        return pt == target
    if DIFFICULTY == 2:
        return pt.upper() == target.upper()
    return target.replace(" ", "") in pt.replace(" ", "").upper()


def serve_file(handler, path: str, label: str) -> None:
    if not os.path.exists(path):
        handler.wfile.write(b"not available\n")
        return
    with open(path, "rb") as f:
        data = base64.b64encode(f.read()).decode()
    handler.wfile.write(f"BEGIN BASE64 {label}\n".encode())
    for i in range(0, len(data), 76):
        handler.wfile.write((data[i:i + 76] + "\n").encode())
    handler.wfile.write(f"END BASE64 {label}\n".encode())


def rc4_submit(pt: str) -> bool:
    return pt == TOKENS["TOKEN4"]


def lfsr_submit(pt: str) -> bool:
    return pt == TOKENS["TOKEN5"]


def pulse_bits():
    for ch in TOKENS["TOKEN6"].encode():
        for i in range(7, -1, -1):
            yield (ch >> i) & 1


def timing_for_bit(bit: int) -> float:
    import random
    base0 = 0.10 if DIFFICULTY <= 2 else 0.12
    base1 = 0.30 if DIFFICULTY <= 2 else 0.32
    jitter = 0.02 if DIFFICULTY <= 2 else 0.025
    return (base0 if bit == 0 else base1) + (random.random() - 0.5) * jitter

def token_to_dns_name(token: str) -> str:
    safe = token.lower()
    safe = safe.replace("{", "-").replace("}", "")
    safe = safe.replace("_", "-")
    safe = safe.replace(":", "-")
    safe = "".join(ch for ch in safe if ch.isalnum() or ch in ".-")
    return f"{safe}.{BEACON_DOMAIN}"

def build_dns_query(name: str) -> bytes:
    txid = os.urandom(2)
    flags = b"\x01\x00"
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    qname = b""
    for label in name.split("."):
        if not label:
            continue
        label_bytes = label.encode("ascii", errors="ignore")[:63]
        qname += bytes([len(label_bytes)]) + label_bytes
    qname += b"\x00"

    qtype = b"\x00\x01"
    qclass = b"\x00\x01"
    return txid + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass


## Networking for TOKEN3

def get_interface_ipv4_and_mask(ifname="eth0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ip = socket.inet_ntoa(
        fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack("256s", ifname.encode()[:15])
        )[20:24]
    )

    mask = socket.inet_ntoa(
        fcntl.ioctl(
            s.fileno(),
            0x891b,  # SIOCGIFNETMASK
            struct.pack("256s", ifname.encode()[:15])
        )[20:24]
    )

    return ip, mask


def compute_broadcast(ifname="eth0"):
    ip, mask = get_interface_ipv4_and_mask(ifname)
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(net.broadcast_address)


def first_non_loopback_interface():
    for _, name in socket.if_nameindex():
        if name != "lo":
            return name
    return "eth0"

def compute_broadcast_auto():
    return compute_broadcast(first_non_loopback_interface())


def get_local_ip():
    candidates = []

    try:
        candidates.extend(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception:
        pass

    for name in ("null-horizon.local", "localhost"):
        try:
            candidates.append(socket.gethostbyname(name))
        except Exception:
            pass

    for ip in candidates:
        if ip and "." in ip and not ip.startswith("127."):
            return ip

    return "127.0.0.1"

def dns_beacon_loop():
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    dst_ip = compute_broadcast("eth0")
    dst_port = 53

    log.info("DNS beacon broadcast target = %s:%s", dst_ip, dst_port)

    while True:
        try:
            token = read_text(DNS_TOKEN_PATH)
            if token:
                qname = token_to_dns_name(token)
                dns_part = build_dns_query(qname)

                # Append exact token so tcpdump -A reveals it directly
                payload = dns_part + b"\n" + token.encode("ascii") + b"\n"

                sock.sendto(payload, (dst_ip, dst_port))
        except Exception as exc:
            log.warning("dns beacon error: %s", exc)

        time.sleep(BEACON_INTERVAL)

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(CLIENT_IDLE_TIMEOUT)

        try:
            self.wfile.write(BANNER.encode())
        except Exception:
            return

        peer = self.client_address

        while True:
            try:
                self.wfile.write(b"\n> ")
                line = self.rfile.readline()
                if not line:
                    break
            except (TimeoutError, socket.timeout, BrokenPipeError, ConnectionResetError, OSError):
                break

            try:
                parts = line.decode(errors="ignore").strip().split()
            except Exception:
                break

            if not parts:
                continue

            cmd = parts[0].lower()

            try:
                if cmd in ("quit", "exit"):
                    self.wfile.write(b"bye\n")
                    break

                elif cmd == "help":
                    self.wfile.write(HELP.encode())

                elif cmd == "about":
                    self.wfile.write(ABOUT.encode())
                    self.wfile.write(
                        fair_hint("Retrieve the UDP spec by sending 'SPEC' to port 30415.").encode()
                    )

                elif cmd == "tokens":
                    for k, v in TOKENS.items():
                        found = "(???)"
                        if k == "TOKEN1" and STATE["handshaked"]:
                            found = v
                        elif k == "TOKEN2" and STATE["frames_ok"]:
                            found = v
                        elif k == "TOKEN3" and STATE["dns_ok"]:
                            found = v
                        elif k == "TOKEN4" and STATE["rc4_ok"]:
                            found = v
                        elif k == "TOKEN5" and STATE["lfsr_ok"]:
                            found = v
                        elif k == "TOKEN6" and STATE["pulse_ok"]:
                            found = v
                        elif k == "TOKEN7" and FINAL_OK_PATH.exists():
                            found = v
                        self.wfile.write(f"{k}: {found}\n".encode())

                elif cmd == "beacon":
                    if len(parts) >= 3 and parts[1] == "submit":
                        pt = " ".join(parts[2:])
                        if pt == TOKENS["TOKEN3"]:
                            STATE["dns_ok"] = True
                            self.wfile.write(f"✅ TOKEN3: {TOKENS['TOKEN3']}\n".encode())
                        else:
                            self.wfile.write("❌ incorrect\n".encode())
                    else:
                        self.wfile.write(b"usage: beacon submit <plaintext>\n")

                elif cmd == "handshake":
                    if len(parts) < 2:
                        self.wfile.write(
                            f"usage: handshake <hex>\n{fair_hint('Compute from UDP spec §2.1: expected = XOR(OPTO,K).')}".encode()
                        )
                        continue
                    expected = compute_expected_handshake(peer)
                    if parts[1].lower() == expected:
                        STATE["handshaked"] = True
                        self.wfile.write(f"✅ link established. TOKEN1: {TOKENS['TOKEN1']}\n".encode())
                        self.wfile.write(
                            fair_hint("Next: decode frames from §2.3 using XOR-shift base from §2.2.").encode()
                        )
                    else:
                        self.wfile.write(
                            f"❌ bad handshake.\n{fair_hint('Send UDP “SPEC” to 30415 to get the definitive spec.')}".encode()
                        )

                elif cmd == "frames":
                    if len(parts) >= 3 and parts[1] == "submit":
                        pt = " ".join(parts[2:])
                        if check_frames(pt):
                            STATE["frames_ok"] = True
                            atomic_write_text(DNS_TOKEN_PATH, TOKENS["TOKEN3"])
                            self.wfile.write(f"✅ frames accepted. TOKEN2: {TOKENS['TOKEN2']}\n".encode())
                            self.wfile.write(b"(a periodic DNS beacon will now leak a token on-wire)\n")
                        else:
                            self.wfile.write("❌ frames rejected.\n".encode())
                    else:
                        self.wfile.write(b"usage: frames submit <plaintext>\n")

                elif cmd == "download":
                    if len(parts) < 2:
                        self.wfile.write(b"usage: download <frames|rc4|lfsr>\n")
                        continue
                    what = parts[1].lower()

                    if what == "frames":
                        frames_hex = encode_frames(LINK_CODE, "null-horizon.local")
                        self.wfile.write(f"FRAMES_HEX {frames_hex}\n".encode())
                        continue

                    path = STATE["downloads"].get(what)
                    if not path:
                        self.wfile.write(b"not available\n")
                        continue
                    serve_file(self, path, what.upper())

                elif cmd == "rc4":
                    if len(parts) >= 3 and parts[1] == "submit":
                        pt = " ".join(parts[2:])
                        if rc4_submit(pt):
                            STATE["rc4_ok"] = True
                            self.wfile.write(f"✅ TOKEN4: {TOKENS['TOKEN4']}\n".encode())
                        else:
                            self.wfile.write("❌ incorrect\n".encode())
                    else:
                        self.wfile.write(b"usage: rc4 submit <plaintext>\n")

                elif cmd == "lfsr":
                    if len(parts) >= 3 and parts[1] == "submit":
                        pt = " ".join(parts[2:])
                        if lfsr_submit(pt):
                            STATE["lfsr_ok"] = True
                            self.wfile.write(f"✅ TOKEN5: {TOKENS['TOKEN5']}\n".encode())
                        else:
                            self.wfile.write("❌ incorrect\n".encode())
                    else:
                        self.wfile.write(b"usage: lfsr submit <plaintext>\n")

                elif cmd == "pulse":
                    if len(parts) == 2 and parts[1] == "start":
                        STATE["pulse_active"] = True
                        STATE["pulse_index"] = 0
                        self.wfile.write(
                            b"Timing channel ready. Issue 'pulse tick' repeatedly to observe delays.\n"
                        )
                        self.wfile.write(
                            fair_hint("Spec §4.3: ~0.1s=0, ~0.3s=1 with small jitter. 8 bits per byte, MSB first.").encode()
                        )
                    elif len(parts) == 2 and parts[1] == "tick":
                        if not STATE["pulse_active"]:
                            self.wfile.write(b"not active; run 'pulse start'\n")
                            continue
                        bits = list(pulse_bits())
                        if STATE["pulse_index"] >= len(bits):
                            self.wfile.write(b"[end of stream]\n")
                            continue
                        b = bits[STATE["pulse_index"]]
                        STATE["pulse_index"] += 1
                        delay = timing_for_bit(b)
                        time.sleep(delay)
                        self.wfile.write(f"PULSE {int(delay * 1000)}ms\n".encode())
                    elif len(parts) == 2 and parts[1] == "stop":
                        STATE["pulse_active"] = False
                        self.wfile.write(b"Timing channel stopped.\n")
                    elif len(parts) >= 3 and parts[1] == "submit":
                        pt = " ".join(parts[2:])
                        if pt == TOKENS["TOKEN6"]:
                            STATE["pulse_ok"] = True
                            STATE["pulse_active"] = False
                            self.wfile.write(f"✅ TOKEN6: {TOKENS['TOKEN6']}\n".encode())
                        else:
                            self.wfile.write("❌ incorrect\n".encode())
                    else:
                        self.wfile.write(b"usage: pulse start|tick|stop|submit <plaintext>\n")

                elif cmd == "finalize":
                    if len(parts) < 2:
                        self.wfile.write(b"usage: finalize <hmac8>\n")
                        continue

                    nonce = read_text(NONCE_PATH)
                    expect = hmac.new(
                        TOKENS["TOKEN6"].encode(),
                        nonce.encode(),
                        hashlib.sha256,
                    ).hexdigest()[-8:]

                    if parts[1].lower() == expect:
                        atomic_write_text(FINAL_OK_PATH, "ok")
                        self.wfile.write(f"✅ TOKEN7: {TOKENS['TOKEN7']}\n".encode())
                    else:
                        self.wfile.write("❌ bad hmac\n".encode())

                else:
                    self.wfile.write(b"unknown command; try 'help'\n")

            except (BrokenPipeError, ConnectionResetError, OSError):
                break
            except Exception as exc:
                log.exception("handler error")
                try:
                    self.wfile.write(f"internal error: {exc}\n".encode())
                except Exception:
                    pass
                break


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_tcp():
    with ThreadedTCPServer(("0.0.0.0", TCP_PORT), Handler) as srv:
        srv.serve_forever()


def serve_udp():
    nonce_ttl = int(os.getenv("NONCE_TTL_SECONDS", "10"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", UDP_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        msg = data.strip().upper()

        if msg == b"SPEC":
            try:
                txt = SPEC_PATH.read_bytes()
            except Exception as exc:
                txt = str(exc).encode()

            for i in range(0, len(txt), 900):
                sock.sendto(txt[i:i + 900], addr)

        elif msg == b"NONCE":
            n = ""
            try:
                if NONCE_PATH.exists():
                    age = time.time() - NONCE_PATH.stat().st_mtime
                    if age < nonce_ttl:
                        n = read_text(NONCE_PATH)
            except Exception:
                n = ""

            if not n:
                n = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
                atomic_write_text(NONCE_PATH, n)

            sock.sendto(("NONCE:" + n).encode(), addr)

        else:
            sock.sendto(b"NOP", addr)


if __name__ == "__main__":
    threading.Thread(target=serve_udp, daemon=True).start()
    threading.Thread(target=dns_beacon_loop, daemon=True).start()
    serve_tcp()