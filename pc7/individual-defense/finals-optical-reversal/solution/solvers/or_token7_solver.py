#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import re
import socket
import time

PROMPT = b"\n> "


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 15.0) -> bytes:
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


def classify_delay(elapsed: float, threshold: float = 0.22) -> int:
    return 1 if elapsed >= threshold else 0


def bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i + 8]:
            b = (b << 1) | bit
        out.append(b)
    return bytes(out)


def recover_token6(sock: socket.socket, max_bytes: int = 64) -> str:
    resp = sendline(sock, "pulse start")
    if "Timing channel ready" not in resp:
        raise RuntimeError("Failed to start timing channel")

    bits: list[int] = []

    for _ in range(max_bytes * 8):
        t0 = time.perf_counter()
        resp = sendline(sock, "pulse tick")
        elapsed = time.perf_counter() - t0

        if "[end of stream]" in resp:
            break

        if "PULSE" not in resp:
            raise RuntimeError(f"Unexpected pulse response: {resp!r}")

        bits.append(classify_delay(elapsed))

        if len(bits) % 8 == 0:
            candidate = bits_to_bytes(bits)
            try:
                decoded = candidate.decode("utf-8")
            except UnicodeDecodeError:
                continue

            m = re.search(r"PCCC\{[A-Za-z0-9\-]+\}", decoded)
            if m:
                return m.group(0)

    raise RuntimeError("Failed to recover TOKEN6 from timing channel")


def fetch_nonce(host: str, udp_port: int, timeout: float = 2.0) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"NONCE", (host, udp_port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    text = data.decode(errors="ignore").strip()
    m = re.match(r"NONCE:([0-9a-fA-F]+)", text)
    if not m:
        raise RuntimeError(f"Unexpected NONCE response: {text!r}")
    return m.group(1)


def compute_finalize_value(token6: str, nonce: str) -> str:
    return hmac.new(token6.encode(), nonce.encode(), hashlib.sha256).hexdigest()[-8:]


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve TOKEN7 for Optical Reversal")
    parser.add_argument("--host", default="null-horizon.local")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--udp-port", type=int, default=30415)
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        banner = recv_prompt(sock)
        if "NULL-HORIZON" not in banner:
            raise RuntimeError("Implant banner not detected")

        token6 = recover_token6(sock)
        print(f"[+] TOKEN6 = {token6}")

        resp = sendline(sock, f"pulse submit {token6}")
        print(resp.rstrip())

        nonce = fetch_nonce(args.host, args.udp_port)
        print(f"[+] NONCE = {nonce}")

        final = compute_finalize_value(token6, nonce)
        print(f"[+] finalize value = {final}")

        resp = sendline(sock, f"finalize {final}")
        print(resp.rstrip())


if __name__ == "__main__":
    main()