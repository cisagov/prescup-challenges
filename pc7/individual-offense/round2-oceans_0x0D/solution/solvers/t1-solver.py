#!/usr/bin/env python3
"""
Token 1 solver (Ocean's 0x0D)

- Subscribes to MQTT roulette rhythm: casino/cage/telemetry/roulette/spin
- Collects a full bucket (slot 0 marker + slots 1..64 carry bits)
- Builds the 16-hex sync code and POSTs /api/ops/sync
- Reads /api/ops/receipt/latest to print TOKEN 1

Requires: pip install paho-mqtt requests
"""

from __future__ import annotations
from typing import Optional, Tuple, Dict

import argparse
import json
import time
from typing import Dict, Optional, Tuple

import requests
import paho.mqtt.client as mqtt


def bits_to_hex64(bits_0_1) -> str:
    # 64 bits -> 8 bytes, MSB-first, then lowercase hex (16 chars)
    out = bytearray()
    for i in range(0, 64, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | (bits_0_1[i + j] & 1)
        out.append(b)
    return out.hex()


def http_json(method: str, url: str, **kwargs) -> dict:
    r = requests.request(method, url, timeout=10, **kwargs)
    if not (200 <= r.status_code < 300):
        try:
            detail = r.json()
        except Exception:
            detail = r.text
        raise RuntimeError(f"{method} {url} -> {r.status_code}: {detail}")
    return r.json()


class BucketCollector:
    def __init__(self):
        self.bucket: Optional[int] = None
        self.slots: Dict[int, int] = {}  # slot -> bit

    def feed(self, msg: dict) -> Optional[Tuple[int, str]]:
    # Guard: ignore non-spin / partial telemetry messages
        if "bucket" not in msg or "slot" not in msg:
            return None

        if msg["bucket"] is None or msg["slot"] is None:
            return None

        try:
            b = int(msg["bucket"])
            slot = int(msg["slot"])
        except (ValueError, TypeError):
            return None

        marker = bool(msg.get("marker", False))
        parity = msg.get("parity")  # "odd" / "even" / None

        # Start a new bucket only on marker slot 0
        if slot == 0 and marker:
            self.bucket = b
            self.slots.clear()
            return None

        if self.bucket is None or b != self.bucket:
            return None

        if 1 <= slot <= 64 and parity in ("odd", "even"):
            self.slots[slot] = 1 if parity == "odd" else 0

        if len(self.slots) == 64:
            bits = [self.slots[i] for i in range(1, 65)]
            code = bits_to_hex64(bits)
            done_bucket = self.bucket

            # reset for next run
            self.bucket = None
            self.slots.clear()

            return (done_bucket, code)

        return None



def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://vaultcore.pccc:8080",required=False, help="e.g. http://vaultcore.pccc:8080")
    ap.add_argument("--mqtt-host", default="roulette-telemetry.pccc")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--mqtt-topic", default="casino/cage/telemetry/roulette/spin")
    ap.add_argument("--timeout", type=int, default=120, help="seconds to wait for a full bucket")
    args = ap.parse_args()

    base = args.base.rstrip("/")

    collector = BucketCollector()
    result: Optional[Tuple[int, str]] = None

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc != 0:
            raise RuntimeError(f"MQTT connect failed rc={rc}")
        client.subscribe(args.mqtt_topic, qos=0)

    def on_message(client, userdata, msg):
        nonlocal result
        try:
            payload = json.loads(msg.payload.decode("utf-8", errors="replace"))
        except Exception:
            return
        got = collector.feed(payload)
        if got:
            result = got
            client.disconnect()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(args.mqtt_host, args.mqtt_port, keepalive=20)

    t0 = time.time()
    while result is None and (time.time() - t0) < args.timeout:
        client.loop(timeout=1.0)

    if result is None:
        raise RuntimeError("Timed out waiting for a full bucket (marker + 64 carrier slots).")

    bucket, code = result
    print(f"[*] Decoded bucket={bucket} sync={code}")

    print("[*] POST /api/ops/sync ...")
    http_json("POST", f"{base}/api/ops/sync", json={"sync": code, "bucket": bucket})

    receipt = http_json("GET", f"{base}/api/ops/receipt/latest")
    print("\n✅ TOKEN 1:", receipt.get("token"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())