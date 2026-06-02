#!/usr/bin/env python3
import argparse
import base64
import hashlib
import re
import socket

PROMPT = b"\n> "
TOKEN_RE = re.compile(rb"PCCC\{[A-Za-z0-9\-]+\}")


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_prompt(sock: socket.socket) -> str:
    return recv_until(sock, PROMPT).decode(errors="ignore")


def sendline(sock: socket.socket, line: str) -> str:
    sock.sendall(line.encode() + b"\n")
    return recv_prompt(sock)


def extract_base64_block(text: str, label: str) -> bytes:
    m = re.search(
        rf"BEGIN BASE64 {re.escape(label)}\n(.*?)\nEND BASE64 {re.escape(label)}",
        text,
        re.DOTALL,
    )
    if not m:
        raise RuntimeError(f"Could not find BASE64 block for {label}")
    blob = "".join(line.strip() for line in m.group(1).splitlines())
    return base64.b64decode(blob)


def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0

    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    out = bytearray()

    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out.append(b ^ k)

    return bytes(out)


def derive_key(ip: str) -> bytes:
    return hashlib.sha1(f"opr:{ip}".encode()).digest()[:16]


def candidate_ips(sock: socket.socket, host: str) -> list[str]:
    out: list[str] = []
    seen = set()

    def add(ip: str) -> None:
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)

    # 1) Most realistic: the actual peer IP of the implant connection
    try:
        add(sock.getpeername()[0])
    except Exception:
        pass

    # 2) Then DNS answers a challenger could learn from normal recon
    try:
        for ip in socket.gethostbyname_ex(host)[2]:
            add(ip)
    except Exception:
        pass

    # 3) Last resort: localhost fallback if the artifact was keyed badly
    add("127.0.0.1")

    return out


def recover_token4(ciphertext: bytes, ips: list[str]) -> tuple[str, str]:
    for ip in ips:
        key = derive_key(ip)
        pt = rc4(ciphertext, key)
        m = TOKEN_RE.search(pt)
        if m:
            return m.group(0).decode("ascii"), ip
    raise RuntimeError("Failed to recover TOKEN4 with peer/DNS/localhost candidates")


def main() -> None:
    parser = argparse.ArgumentParser(description="Optical Reversal TOKEN4 solver")
    parser.add_argument("--host", default="null-horizon.local")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--submit", action="store_true")
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        banner = recv_prompt(sock)
        if "NULL-HORIZON" not in banner:
            raise RuntimeError("Implant banner not detected")

        resp = sendline(sock, "download rc4")
        ct = extract_base64_block(resp, "RC4")

        ips = candidate_ips(sock, args.host)
        print(f"[+] Candidate IPs (in order): {', '.join(ips)}")

        token, key_ip = recover_token4(ct, ips)
        key = derive_key(key_ip)

        print(f"[+] Key IP used: {key_ip}")
        print(f"[+] RC4 key: {key.hex()}")
        print(f"[+] TOKEN4 = {token}")

        if args.submit:
            resp = sendline(sock, f"rc4 submit {token}")
            print(resp.rstrip())


if __name__ == "__main__":
    main()