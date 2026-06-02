#!/usr/bin/env python3
import json
from pathlib import Path

frames = []
for line in Path("replay_journal.ndjson").read_text().splitlines():
    item = json.loads(line)
    if item.get("tag") == "silent-step":
        seq = int(item["seq"])
        raw = bytes.fromhex(item["frame_hex"])
        payload = raw[7:]
        frames.append((seq, bytes(b ^ 0x4e for b in payload)))

token = b"".join(chunk for _, chunk in sorted(frames)).decode()
print(token)