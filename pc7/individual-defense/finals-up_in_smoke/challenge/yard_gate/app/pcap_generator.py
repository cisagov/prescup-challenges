#!/usr/bin/env python3
import hashlib
import os
import random
import secrets

from scapy.all import IP, PcapWriter, Raw, UDP, conf

# ---- Scapy hardening ----
conf.verb = 0
conf.use_pcap = True

# ---- Environment / paths ----
PCAP_PROFILE = os.environ.get("PCAP_PROFILE", "25k").lower()
PCAP_PATH = "/opt/yard/telemetry/yard_traffic.pcap"

# ---- Network model ----
YARD_IP = "172.18.0.5"
VENDOR_IP = "172.18.0.9"
PORT = 9001

VALID_TRAILER = "TRUCK-777"
MAC_KEY = b"\x91\xad\x23\x88\xfa\x01\xbc\x77"

STATE_LOCKED = "LOCKED"
STATE_CLOSED = "CLOSED"
STATE_OPEN = "OPEN"

# ---- Packet counts ----
if PCAP_PROFILE == "150k":
    TOTAL_PACKETS = 150_000
else:
    TOTAL_PACKETS = 25_000

SUCCESS_CHAINS = 3  # invariant


def mac(trailer, nonce, session, state):
    blob = (
        MAC_KEY
        + trailer.encode()
        + nonce.encode()
        + session.encode()
        + state.encode()
    )
    return hashlib.sha1(blob).digest()


def diagnostic_packets():
    return [
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT, dport=PORT)
        / Raw(load=b"YARD_CTRL: legacy vendor MAC is still enabled"),
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT, dport=PORT)
        / Raw(load=b"CTRL_NOTE: MAC=SHA1(KEY|TRAILER|NONCE|SESSION|STATE)"),
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT, dport=PORT)
        / Raw(load=f"LEAK:{MAC_KEY.hex()}".encode()),
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT, dport=PORT)
        / Raw(load=f"TRAILER:{VALID_TRAILER}".encode()),
    ]


def noise_packet():
    src = random.choice([YARD_IP, VENDOR_IP])
    dst = VENDOR_IP if src == YARD_IP else YARD_IP
    return (
        IP(src=src, dst=dst)
        / UDP(sport=random.randint(20000, 40000), dport=PORT)
        / Raw(load=secrets.token_bytes(random.randint(24, 64)))
    )


def failed_attempt(writer):
    session = secrets.token_hex(4)
    nonce = secrets.token_hex(4)

    writer.write(
        IP(src=VENDOR_IP, dst=YARD_IP)
        / UDP(dport=PORT)
        / Raw(load=b"HELLO" + session.encode())
    )
    writer.write(
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT)
        / Raw(load=b"NONCE" + nonce.encode())
    )
    writer.write(
        IP(src=VENDOR_IP, dst=YARD_IP)
        / UDP(dport=PORT)
        / Raw(load=secrets.token_bytes(20))
    )
    writer.write(
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT)
        / Raw(load=b"ACK_FAIL")
    )


def successful_chain(writer):
    session = secrets.token_hex(4)
    nonce = secrets.token_hex(4)

    # Session establishment
    writer.write(
        IP(src=VENDOR_IP, dst=YARD_IP)
        / UDP(dport=PORT)
        / Raw(load=b"HELLO" + session.encode())
    )
    writer.write(
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT)
        / Raw(load=b"NONCE" + nonce.encode())
    )

    # LOCKED -> CLOSED
    lock_close_mac = mac(VALID_TRAILER, nonce, session, STATE_LOCKED)
    writer.write(
        IP(src=VENDOR_IP, dst=YARD_IP)
        / UDP(dport=PORT)
        / Raw(load=lock_close_mac)
    )
    writer.write(
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT)
        / Raw(load=b"ACK_CLOSED")
    )

    # CLOSED -> OPEN
    open_mac = mac(VALID_TRAILER, nonce, session, STATE_CLOSED)
    writer.write(
        IP(src=VENDOR_IP, dst=YARD_IP)
        / UDP(dport=PORT)
        / Raw(load=open_mac)
    )
    writer.write(
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT)
        / Raw(load=b"ACK_OPEN")
    )
    writer.write(
        IP(src=YARD_IP, dst="255.255.255.255")
        / UDP(sport=PORT, dport=PORT)
        / Raw(load=b"GATE_OPEN")
    )

    # OPEN -> CLOSED
    close_mac = mac(VALID_TRAILER, nonce, session, STATE_OPEN)
    writer.write(
        IP(src=VENDOR_IP, dst=YARD_IP)
        / UDP(dport=PORT)
        / Raw(load=close_mac)
    )
    writer.write(
        IP(src=YARD_IP, dst=VENDOR_IP)
        / UDP(sport=PORT)
        / Raw(load=b"ACK_CLOSED")
    )
    writer.write(
        IP(src=YARD_IP, dst="255.255.255.255")
        / UDP(sport=PORT, dport=PORT)
        / Raw(load=b"GATE_CLOSED")
    )


def generate():
    os.makedirs(os.path.dirname(PCAP_PATH), exist_ok=True)

    writer = PcapWriter(PCAP_PATH, append=False, sync=True)

    try:
        for pkt in diagnostic_packets():
            writer.write(pkt)

        noise_target = int(TOTAL_PACKETS * 0.60)
        fail_target = int(TOTAL_PACKETS * 0.35)

        for _ in range(noise_target):
            writer.write(noise_packet())

        for _ in range(fail_target // 4):
            failed_attempt(writer)

        for _ in range(SUCCESS_CHAINS):
            successful_chain(writer)

    finally:
        writer.close()


if __name__ == "__main__":
    print(f"[*] Generating yard traffic PCAP ({PCAP_PROFILE.upper()})")
    generate()
    print(f"[*] PCAP written to {PCAP_PATH}")