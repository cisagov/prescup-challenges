#!/usr/bin/env python3
"""Generate eng-bell-04-outbound.pcap — a TCP capture of the implant's
outbound handshake to bore.pub:7835. Used once at challenge build time;
the resulting PCAP is committed alongside the other static artifacts.

Usage:
    python3 build_pcap.py  # writes eng-bell-04-outbound.pcap into cwd

The capture shows: 3-way handshake, the handler's random hex challenge
(server -> client), the implant's SHA256 hex digest reply (client ->
server), the server returning a placeholder value, FIN/ACK shutdown.

The actual TOKEN5 is NOT in this PCAP — the implant's `bore.pub` C2
returns a sentinel string; the real token comes from competitors
replaying the handshake against the live c2-replay container.
"""
from __future__ import annotations

import hashlib
import base64
import pathlib
from datetime import datetime, timezone

from scapy.all import IP, TCP, Raw, Ether, wrpcap


CLIENT_IP = "10.42.99.14"
CLIENT_PORT = 51284
SERVER_IP = "159.65.207.62"   # bore.pub IPv4 at capture time
SERVER_PORT = 7835

CLIENT_MAC = "02:42:0a:2a:63:0e"
SERVER_MAC = "02:42:cc:af:0e:42"


def _pkt(client_to_server: bool, flags: str, seq: int, ack: int, payload: bytes = b"") -> bytes:
    if client_to_server:
        eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        ip = IP(src=CLIENT_IP, dst=SERVER_IP)
        tcp = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags=flags, seq=seq, ack=ack, window=65535)
    else:
        eth = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        ip = IP(src=SERVER_IP, dst=CLIENT_IP)
        tcp = TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags=flags, seq=seq, ack=ack, window=65535)
    return eth / ip / tcp / Raw(load=payload) if payload else eth / ip / tcp


def main() -> int:
    # Deterministic but realistic challenge + handshake reply.
    challenge = b"5a2c4f1e9b6d3a7c8e0f1d2b4a6c8e0f"   # 32 hex chars (16 random bytes hexlified)
    encoded_password = base64.b64encode(b"changeme123")
    reply = hashlib.sha256(challenge + encoded_password).hexdigest().encode("ascii")
    # bore.pub's tunnel returns a sentinel; the real handler is downstream.
    server_response = b"OK 7835\n"

    base = datetime(2026, 5, 12, 2, 17, 2, tzinfo=timezone.utc).timestamp()

    seq_c = 1_000_000
    seq_s = 2_000_000
    packets = []

    p = _pkt(True, "S", seq_c, 0); p.time = base + 0.000; packets.append(p)
    p = _pkt(False, "SA", seq_s, seq_c + 1); p.time = base + 0.012; packets.append(p)
    p = _pkt(True, "A", seq_c + 1, seq_s + 1); p.time = base + 0.013; packets.append(p)

    # Server -> client: challenge + newline (33 bytes)
    challenge_payload = challenge + b"\n"
    p = _pkt(False, "PA", seq_s + 1, seq_c + 1, challenge_payload); p.time = base + 0.045; packets.append(p)
    p = _pkt(True, "A", seq_c + 1, seq_s + 1 + len(challenge_payload)); p.time = base + 0.046; packets.append(p)

    # Client -> server: SHA256 hex digest + newline (65 bytes)
    reply_payload = reply + b"\n"
    p = _pkt(True, "PA", seq_c + 1, seq_s + 1 + len(challenge_payload), reply_payload); p.time = base + 0.061; packets.append(p)
    p = _pkt(False, "A", seq_s + 1 + len(challenge_payload), seq_c + 1 + len(reply_payload)); p.time = base + 0.062; packets.append(p)

    # Server -> client: sentinel response
    p = _pkt(False, "PA", seq_s + 1 + len(challenge_payload), seq_c + 1 + len(reply_payload), server_response); p.time = base + 0.099; packets.append(p)
    p = _pkt(True, "A", seq_c + 1 + len(reply_payload), seq_s + 1 + len(challenge_payload) + len(server_response)); p.time = base + 0.100; packets.append(p)

    # FIN exchange
    p = _pkt(True, "FA", seq_c + 1 + len(reply_payload), seq_s + 1 + len(challenge_payload) + len(server_response)); p.time = base + 0.150; packets.append(p)
    p = _pkt(False, "FA", seq_s + 1 + len(challenge_payload) + len(server_response), seq_c + 2 + len(reply_payload)); p.time = base + 0.152; packets.append(p)
    p = _pkt(True, "A", seq_c + 2 + len(reply_payload), seq_s + 2 + len(challenge_payload) + len(server_response)); p.time = base + 0.153; packets.append(p)

    out = pathlib.Path("eng-bell-04-outbound.pcap")
    wrpcap(str(out), packets)
    print(f"wrote {out}: {out.stat().st_size} bytes ({len(packets)} packets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
