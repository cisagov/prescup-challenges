#!/usr/bin/env python3
import base64
import gzip
import hashlib
import json
import os
import shutil
import socket
import struct
import time
import zipfile
from pathlib import Path

DATA_ROOT = Path("/data")
BUILD_ROOT = Path("/tmp/shunpo-build")
EVIDENCE_ROOT = BUILD_ROOT / "evidence"


def _chunk_text(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def _encode_dns_labels(token: str) -> list[str]:
    compressed = gzip.compress(token.encode("utf-8"))
    encoded = base64.b32encode(compressed).decode("ascii").rstrip("=").lower()
    return [f"{index:02d}{chunk}.telemetry.kitsune.internal" for index, chunk in enumerate(_chunk_text(encoded, 12))]


def _ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac_from_octet(octet: int) -> bytes:
    return bytes([0x02, 0x42, 0xAC, 0x11, 0x00, octet & 0xFF])


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _build_dns_query_payload(qname: str, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(qname) + struct.pack("!HH", 1, 1)
    return header + question


def _build_udp_frame(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes, packet_id: int) -> bytes:
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", sport, dport, udp_length, 0)

    total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        packet_id & 0xFFFF,
        0,
        64,
        17,
        0,
        src_ip_bytes,
        dst_ip_bytes,
    )
    checksum = _ip_checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        packet_id & 0xFFFF,
        0,
        64,
        17,
        checksum,
        src_ip_bytes,
        dst_ip_bytes,
    )

    eth = _mac_from_octet(packet_id + 1) + _mac_from_octet(packet_id + 2) + struct.pack("!H", 0x0800)
    return eth + ip_header + udp_header + payload


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts_base = int(time.time())
        for index, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", ts_base + index, 0, len(frame), len(frame)))
            handle.write(frame)


def _build_stage1_pcap(path: Path, labels: list[str]) -> None:
    frames = []
    noise = [
        "www.example.com",
        "updates.vendor.net",
        "cdn.telemetry.local",
        "time.pool.ntp.org",
    ]
    for index, name in enumerate(noise + labels):
        src = f"10.77.0.{50 + (index % 4)}"
        dst = "10.77.0.2"
        payload = _build_dns_query_payload(name, 0x3300 + index)
        frames.append(_build_udp_frame(src, dst, 53000 + index, 53, payload, index + 1))
    _write_pcap(path, frames)


def _build_stage3_pcap(path: Path, token3: str) -> None:
    frames = []
    ascii_payload = "\n".join(
        [
            "PUT /firmware/update.bin.enc",
            "X-Device-ID: kitsune-cam-alpha",
            "X-Channel: prod",
            "X-Profile: xor-lcg-gzip",
            f"X-Cleartext-Len: {len(token3)}",
            "",
        ]
    ).encode("utf-8")
    frames.append(_build_udp_frame("10.77.0.30", "10.77.0.99", 56830, 5683, ascii_payload, 80))
    frames.append(_build_udp_frame("10.77.0.31", "10.77.0.99", 56831, 5683, b"GET /.well-known/core", 81))
    _write_pcap(path, frames)


def _lcg_keystream(seed_high: int, seed_low: int, size: int, multiplier: int, increment: int) -> bytes:
    seed = ((seed_high & 0xFFFF) << 16) | (seed_low & 0xFFFF)
    state = seed
    out = bytearray()
    for _ in range(size):
        state = (state * multiplier + increment) & 0xFFFFFFFF
        out.append((state >> 16) & 0xFF)
    return bytes(out)


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key))


def build() -> None:
    token1 = os.environ.get("TOKEN1", "PCCC{SHN-A1-7f3a9c2b}")
    token2 = os.environ.get("TOKEN2", "PCCC{SHN-A2-f9277cad}")
    token3 = os.environ.get("TOKEN3", "PCCC{SHN-A3-9d30347e}")
    token4 = os.environ.get("TOKEN4", "PCCC{SHN-A4-a842ec49}")
    token5 = os.environ.get("TOKEN5", "PCCC{SHN-A5-4e1d9a7c}")

    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    if EVIDENCE_ROOT.exists():
        shutil.rmtree(EVIDENCE_ROOT)
    (EVIDENCE_ROOT / "static").mkdir(parents=True, exist_ok=True)
    (EVIDENCE_ROOT / "artifacts").mkdir(parents=True, exist_ok=True)
    (EVIDENCE_ROOT / "files").mkdir(parents=True, exist_ok=True)

    labels = _encode_dns_labels(token1)
    _build_stage1_pcap(EVIDENCE_ROOT / "static" / "pcap_stage1.pcap", labels)
    _build_stage3_pcap(EVIDENCE_ROOT / "static" / "pcap_stage3.pcap", token3)

    resolver_lines = [
        "2026-03-14T20:32:01Z resolver[1234]: qname=www.example.com status=NOERROR proto=dns_plain tag=normal"
    ]
    for index, label in enumerate(labels):
        resolver_lines.append(
            f"2026-03-14T20:32:{index + 3:02d}Z resolver[1234]: "
            f"qname={label} status=NXDOMAIN proto=dns_b32+gzip tag=flash-beacon segment={index:02d}"
        )
    (EVIDENCE_ROOT / "artifacts" / "resolver.log").write_text("\n".join(resolver_lines) + "\n", encoding="utf-8")

    digest = hashlib.sha256(token3.encode("utf-8")).digest()
    seed_high = int.from_bytes(digest[:2], "big")
    seed_low = int.from_bytes(digest[2:4], "big")
    multiplier = 0x045D9F3B
    increment = 0x1337

    compressed = gzip.compress(token3.encode("utf-8"))
    keystream = _lcg_keystream(seed_high, seed_low, len(compressed), multiplier, increment)
    ciphertext = _xor(compressed, keystream)
    (EVIDENCE_ROOT / "files" / "update.bin.enc").write_bytes(ciphertext)

    device_config = {
        "device_id": "kitsune-cam-alpha",
        "model": "KTS-CAM-01",
        "firmware_channel": "prod",
        "update_endpoint": "coap://sp-coap.ninja/firmware/update.bin.enc",
        "update_filename": "update.bin.enc",
        "crypto": {
            "scheme": "xor-lcg-gzip",
            "seed_assembly": "seed = (SEED_HIGH << 16) | SEED_LOW",
            "seed_high_ref": "see key_part_a.txt",
            "seed_low_ref": "see key_part_b.txt",
            "multiplier": hex(multiplier),
            "increment": hex(increment),
            "notes": "plaintext -> gzip -> XOR keystream; keystream_byte = ((state * multiplier + increment) >> 16) & 0xff",
        },
    }
    (EVIDENCE_ROOT / "artifacts" / "device_config.json").write_text(
        json.dumps(device_config, indent=2) + "\n", encoding="utf-8"
    )
    (EVIDENCE_ROOT / "artifacts" / "key_part_a.txt").write_text(
        f"Label : SEED_HIGH\nValue : 0x{seed_high:04x}\n", encoding="utf-8"
    )
    (EVIDENCE_ROOT / "artifacts" / "key_part_b.txt").write_text(
        f"Label : SEED_LOW\nValue : 0x{seed_low:04x}\n", encoding="utf-8"
    )

    (EVIDENCE_ROOT / "artifacts" / "silent_step_reference.txt").write_text(
        "\n".join(
            [
                "Silent Step replay notes",
                "- Trigger replay from the dashboard and export the replay journal.",
                "- Relevant frames are tagged `silent-step`.",
                "- Each frame preserves a 7-byte control leader: 13 37 20 <seq> 13 37 <seq>.",
                "- The payload bytes were scrubbed with a single guard byte.",
                "- guard = (0x13 + 0x37 + burst_count) & 0xff",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (EVIDENCE_ROOT / "artifacts" / "operations_memo.txt").write_text(
        "\n".join(
            [
                "Operations memo",
                "- Dashboard: http://sp-dashboard.ninja:3000",
                "- Operations panel: http://sp-ops.ninja:8080",
                "- Operator username remains `opsadmin`.",
                "- Response detail can be raised after sign-in from the operations dashboard.",
                "- Replay exports include prior maintenance activity and encoded route fragments.",
                "- The bridge ticket recovered from the internal brief is reused by the constrained bridge.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    bridge_note = {
        "codename": "Kitsune",
        "notes": [
            "Prefers chained recoveries over one-shot exfiltration.",
            "Reused operational material across dashboard, relay, and bridge tooling.",
            "Night crossing procedures rely on ticketed bridge access after relay restoration.",
        ],
        "service_index": {
            "dashboard": "http://sp-dashboard.ninja:3000",
            "ops_panel": "http://sp-ops.ninja:8080",
            "coap_service": "coap://sp-coap.ninja",
        },
        "tokens_progression": [
            "Token 1 -> ops panel password",
            "Token 2 -> route key",
            "Token 3 -> signing material",
            "Token 4 -> bridge ticket",
            "Token 5 -> final relay token",
        ],
    }
    (EVIDENCE_ROOT / "artifacts" / "agent_profile.json").write_text(
        json.dumps(bridge_note, indent=2) + "\n", encoding="utf-8"
    )

    mission = f"""# SHUNPO – Mission Briefing

Kitsune vanished during a fast-moving support mission that chained together three kinds of tradecraft:
forensic fragments, trusted relay abuse, and a constrained bridge escape.

## Situation

Recovered material points to a dashboard used as an evidence portal, a restricted operations panel, and a CoAP maintenance bridge.
The first three recoveries are deterministic and come from evidence plus replay exports.
The last two require you to reuse recovered material against live services.

## Objectives

All answers are tokens of the form:

`PCCC{{SHN-A#-xxxxxxxx}}`

### Token 1 – Flash Beacon

- Inspect `static/pcap_stage1.pcap`.
- Use `artifacts/resolver.log` to isolate the flash-beacon labels.
- Reassemble the base32 payload, restore padding, decode, and decompress.
- The recovered token is also the operations panel password.

### Token 2 – Silent Step

- Trigger replay from the dashboard.
- Download the replay journal after the cycle completes.
- Extract the `silent-step` frames, remove the 7-byte control leader, and reverse the guard-byte scrubbing described in `artifacts/silent_step_reference.txt`.
- The recovered token is also the route key used by both relays.

### Token 3 – Shadow Load

- Inspect `static/pcap_stage3.pcap` and `artifacts/device_config.json`.
- Reconstruct the 32-bit seed using `key_part_a.txt` and `key_part_b.txt`.
- Decrypt `files/update.bin.enc` and decompress the result.
- The recovered token is also the internal signing key.

### Token 4 – Relay Restore

- Sign in to the operations panel with the recovered password.
- Raise response detail if you need richer diagnostics.
- Exploit the maintenance relay trust boundary so the first hop looks trusted while the terminal destination reaches the loopback-only internal brief.
- The recovered token is also the bridge ticket.

### Token 5 – Night Crossing

- Use the bridge ticket with the constrained CoAP relay.
- Abuse the namespace translation flaw to reach the hidden admin workflow.
- Complete bootstrap, material, and finalize in order.
- Recover the final relay token.

## Rules of Engagement

- Interact only with challenge hosts on the competitor segment.
- Do not attack the challenge platform itself.
- Preserve timestamps in your crafted requests; both relays enforce time windows.

Good hunting.
"""
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    (DATA_ROOT / "mission_briefing.md").write_text(mission, encoding="utf-8")

    package_path = DATA_ROOT / "evidence-package.zip"
    with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for item in sorted(EVIDENCE_ROOT.rglob("*")):
            if item.is_file():
                archive.write(item, item.relative_to(EVIDENCE_ROOT))

    (DATA_ROOT / "build-metadata.json").write_text(
        json.dumps(
            {
                "token2_preview": token2[:8] + "...",
                "token4_preview": token4[:8] + "...",
                "token5_preview": token5[:8] + "...",
                "generator": "dashboard/bootstrap/generate_data.py",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build()
