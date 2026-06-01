#!/usr/bin/env python3
import argparse
import base64
import re
import socket

PROMPT = b"\n> "


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


def lfsr_next(state_ref: list[int]) -> int:
    state = state_ref[0]
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

    state_ref[0] = state
    return out


def recover_token5(ciphertext: bytes) -> str:
    state_ref = [0xA7]
    keystream = bytes(lfsr_next(state_ref) for _ in range(len(ciphertext)))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    token = plaintext.decode("utf-8")
    if not re.fullmatch(r"PCCC\{[A-Za-z0-9\-]+\}", token):
        raise RuntimeError(f"Recovered plaintext does not look like TOKEN5: {token!r}")
    return token


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve TOKEN5 for Optical Reversal")
    parser.add_argument("--host", default="null-horizon.local")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--submit", action="store_true")
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        banner = recv_prompt(sock)
        if "NULL-HORIZON" not in banner:
            raise RuntimeError("Implant banner not detected")

        resp = sendline(sock, "download lfsr")
        ct = extract_base64_block(resp, "LFSR")

        token5 = recover_token5(ct)
        print(f"[+] TOKEN5 = {token5}")

        if args.submit:
            resp = sendline(sock, f"lfsr submit {token5}")
            print(resp.rstrip())


if __name__ == "__main__":
    main()