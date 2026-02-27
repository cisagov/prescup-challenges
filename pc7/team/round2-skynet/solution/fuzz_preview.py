#!/usr/bin/env python3

#fuzz_preview.py

import argparse
import json
import struct
import sys
import requests

MAC_LEN = 32
LEN_LEN = 4

def split_wrapped(file_bytes: bytes):
    if len(file_bytes) < MAC_LEN + LEN_LEN:
        raise ValueError("file too small")
    mac = file_bytes[-MAC_LEN:]
    payload_len = struct.unpack(">I", file_bytes[-(MAC_LEN+LEN_LEN):-MAC_LEN])[0]
    enc = file_bytes[:-(MAC_LEN+LEN_LEN)]
    return enc, payload_len, mac

def region_of_offset(file_len: int, off: int) -> str:
    if off < file_len - (MAC_LEN + LEN_LEN):
        return "encoded_payload"
    if off < file_len - MAC_LEN:
        return "payload_len_field"
    return "mac_field"

def hexdump_window(buf: bytes, off: int, radius: int = 16) -> str:
    start = max(0, off - radius)
    end = min(len(buf), off + radius + 1)
    chunk = buf[start:end]
    # mark mutated byte with brackets
    rel = off - start
    parts = []
    for i, b in enumerate(chunk):
        s = f"{b:02x}"
        if i == rel:
            s = f"[{s}]"
        parts.append(s)
    return f"0x{start:08x}..0x{end-1:08x}: " + " ".join(parts)

def summarize(preview_json: dict) -> dict:
    out = {
        "trackCount": preview_json.get("trackCount"),
        "payloadLen": preview_json.get("payloadLen"),
        "tracks": []
    }
    for t in preview_json.get("tracks", []):
        pts = t.get("points", [])
        out["tracks"].append({
            "name": t.get("name"),
            "pointCount": len(pts),
            "start": pts[0].get("t_iso") if pts else None,
            "end": pts[-1].get("t_iso") if pts else None,
        })
    return out

def diff_summary(a: dict, b: dict) -> list[str]:
    diffs = []
    if a.get("trackCount") != b.get("trackCount"):
        diffs.append(f"trackCount: {a.get('trackCount')} -> {b.get('trackCount')}")
    if a.get("payloadLen") != b.get("payloadLen"):
        diffs.append(f"payloadLen: {a.get('payloadLen')} -> {b.get('payloadLen')}")

    ta = a.get("tracks", [])
    tb = b.get("tracks", [])
    if len(ta) != len(tb):
        diffs.append(f"tracks length: {len(ta)} -> {len(tb)}")

    n = min(len(ta), len(tb))
    for i in range(n):
        if ta[i]["name"] != tb[i]["name"]:
            diffs.append(f"tracks[{i}].name: {ta[i]['name']} -> {tb[i]['name']}")
        if ta[i]["pointCount"] != tb[i]["pointCount"]:
            diffs.append(f"tracks[{i}].pointCount: {ta[i]['pointCount']} -> {tb[i]['pointCount']}")
        if ta[i]["start"] != tb[i]["start"]:
            diffs.append(f"tracks[{i}].start: {ta[i]['start']} -> {tb[i]['start']}")
        if ta[i]["end"] != tb[i]["end"]:
            diffs.append(f"tracks[{i}].end: {ta[i]['end']} -> {tb[i]['end']}")
    return diffs

def preview(base_url: str, file_bytes: bytes) -> dict:
    r = requests.post(
        f"{base_url}/preview",
        files={"file": ("coords.bin", file_bytes, "application/octet-stream")},
        timeout=30,
    )
    try:
        return r.json()
    except Exception:
        return {"error": "BAD_JSON", "status": r.status_code, "text": r.text[:5000]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://skynet")
    ap.add_argument("--file", default="coords.bin")
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0, help="start offset into encoded payload")
    ap.add_argument("--end", type=lambda x: int(x, 0), default=None, help="end offset into encoded payload (exclusive)")
    ap.add_argument("--step", type=int, default=1)
    ap.add_argument("--xor", type=lambda x: int(x, 0), default=0x01)
    ap.add_argument("--limit", type=int, default=0, help="stop after N hits (0 = no limit)")
    args = ap.parse_args()

    original = open(args.file, "rb").read()
    enc, payload_len, mac = split_wrapped(original)
    encoded_len = len(enc)

    # Default: fuzz entire encoded payload
    start = max(0, args.start)
    end = encoded_len if args.end is None else min(args.end, encoded_len)

    print(f"[i] file_len={len(original)} encoded_len={encoded_len} payload_len={payload_len} footer=36")
    print(f"[i] fuzz range in encoded payload: 0x{start:x}..0x{end:x} step={args.step} xor=0x{args.xor:02x}")

    base_resp = preview(args.base_url, original)
    if "error" in base_resp:
        print("Baseline preview error:", base_resp, file=sys.stderr)
        sys.exit(1)
    base_sum = summarize(base_resp)

    hits = 0
    for off_in_enc in range(start, end, args.step):
        mutated = bytearray(original)
        # off in full file is same as off in enc (enc starts at 0)
        file_off = off_in_enc
        mutated[file_off] ^= args.xor

        resp = preview(args.base_url, bytes(mutated))
        if "error" in resp:
            # Only print failures if you want; noisy otherwise
            continue

        new_sum = summarize(resp)
        diffs = diff_summary(base_sum, new_sum)
        if not diffs:
            continue

        hits += 1
        reg = region_of_offset(len(original), file_off)
        print(f"\n[file_off=0x{file_off:08x}] region={reg} enc_off=0x{off_in_enc:08x} (orig={original[file_off]:02x} new={mutated[file_off]:02x})")
        print("  bytes:", hexdump_window(original, file_off, radius=16))
        for d in diffs:
            print("  ->", d)

        if args.limit and hits >= args.limit:
            break

if __name__ == "__main__":
    main()
