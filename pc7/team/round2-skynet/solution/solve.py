#!/usr/bin/env python3

#solve.py

import struct
import math

# ---- Affine256 params ----
A = 5
B = 34 #0x22
A_INV = 205
MOD = 256

INFILE = 'coords.bin'
OUTFILE = 'coords_mod.bin'

FOOTER_LEN = 36  # 4 bytes payload_len + 32 bytes mac (preserved)

def affine_decode(buf: bytes) -> bytes:
    out = bytearray(len(buf))
    for i, c in enumerate(buf):
        out[i] = (A_INV * ((c - B) & 0xFF)) & 0xFF
    return bytes(out)

def affine_encode(buf: bytes) -> bytes:
    out = bytearray(len(buf))
    for i, p in enumerate(buf):
        out[i] = (A * p + B) & 0xFF
    return bytes(out)

# ---- Binary parsing/serialization for your payload format ----
def parse_payload(payload: bytes):
    off = 0
    def need(n):
        if off + n > len(payload):
            raise ValueError(f"parse past end at 0x{off:x}, need {n}")

    need(4)
    track_count = struct.unpack_from(">I", payload, off)[0]
    off += 4

    tracks = []
    for _ in range(track_count):
        need(4)
        name_len = struct.unpack_from(">I", payload, off)[0]
        off += 4

        need(name_len)
        name = payload[off:off+name_len].decode("utf-8", errors="strict")
        off += name_len

        need(4)
        point_count = struct.unpack_from(">I", payload, off)[0]
        off += 4

        points = []
        for __ in range(point_count):
            need(24)
            t_ms = struct.unpack_from(">Q", payload, off)[0]; off += 8
            lat  = struct.unpack_from(">d", payload, off)[0]; off += 8
            lon  = struct.unpack_from(">d", payload, off)[0]; off += 8
            points.append([t_ms, lat, lon])

        tracks.append({"name": name, "points": points})

    return track_count, tracks, off

def serialize_payload(tracks):
    chunks = []
    chunks.append(struct.pack(">I", len(tracks)))
    for tr in tracks:
        name_bytes = tr["name"].encode("utf-8")
        chunks.append(struct.pack(">I", len(name_bytes)))
        chunks.append(name_bytes)
        pts = tr["points"]
        chunks.append(struct.pack(">I", len(pts)))
        for (t_ms, lat, lon) in pts:
            chunks.append(struct.pack(">Q", int(t_ms)))
            chunks.append(struct.pack(">d", float(lat)))
            chunks.append(struct.pack(">d", float(lon)))
    return b"".join(chunks)

# ---- Helpers to compute "not in US" and longest path ----
def haversine_m(lat1, lon1, lat2, lon2):
    # meters
    R = 6371000.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dlmb/2)**2
    return 2*R*math.asin(math.sqrt(a))

def total_path_m(points):
    if len(points) < 2:
        return 0.0
    total = 0.0
    for i in range(1, len(points)):
        _, lat1, lon1 = points[i-1]
        _, lat2, lon2 = points[i]
        total += haversine_m(lat1, lon1, lat2, lon2)
    return total

def duration_ms(points):
    if len(points) < 2:
        return 0
    return int(points[-1][0]) - int(points[0][0])

def in_us_rough(lat, lon):
    # Exclude Canadian territory near Toronto
    if 43.0 <= lat <= 44.5 and -80.5 <= lon <= -78.0:
        return False
    # CONUS
    if 24.0 <= lat <= 49.5 and -125.0 <= lon <= -66.0:
        return True
    # Alaska
    if 51.0 <= lat <= 72.0 and -170.0 <= lon <= -129.0:
        return True
    return False

def track_is_in_us(tr):
    pts = tr["points"]
    if not pts:
        return True
    # decide by first point
    _, lat, lon = pts[0]
    return in_us_rough(lat, lon)

# ---- The required modifications ----
def apply_mods(tracks):
    # Q1: last name alphabetically -> rename to Jet Streamer
    names_sorted = sorted([t["name"] for t in tracks])
    last_name = names_sorted[-1]
    for t in tracks:
        if t["name"] == last_name:
            t["name"] = "Jet Streamer"
            break

    # Q2: only drone not located within US -> reduce lat/lon by 5
    non_us = [t for t in tracks if not track_is_in_us(t)]
    if len(non_us) != 1:
        raise ValueError(f"expected exactly 1 non-US drone, found {len(non_us)}")
    t2 = non_us[0]
    for p in t2["points"]:
        p[1] -= 5.0  # lat
        p[2] -= 5.0  # lon

    # Q3: longest flight time -> add 3 seconds between each coordinate
    t3 = max(tracks, key=lambda t: duration_ms(t["points"]))
    pts = t3["points"]
    if len(pts) >= 2:
        new_pts = [pts[0][:]]
        for i in range(1, len(pts)):
            prev_t = new_pts[i-1][0]
            orig_dt = int(pts[i][0]) - int(pts[i-1][0])
            new_t = int(prev_t) + int(orig_dt) + 3000  # +3 seconds per segment
            new_pts.append([new_t, pts[i][1], pts[i][2]])
        t3["points"] = new_pts

    # Q4: longest flight path -> reverse the point order
    t4 = max(tracks, key=lambda t: total_path_m(t["points"]))
    pts = t4["points"]
    if len(pts) >= 2:
        times = [p[0] for p in pts]                 # keep original t_ms order
        coords = [(p[1], p[2]) for p in pts]        # (lat, lon)
        coords.reverse()                             # reverse spatial path

        t4["points"] = [[times[i], coords[i][0], coords[i][1]] for i in range(len(pts))]


    return last_name, t2["name"], t3["name"], t4["name"]

def main():
    raw = open(INFILE, "rb").read()
    if len(raw) < FOOTER_LEN:
        raise SystemExit("file too small")

    encoded = raw[:-FOOTER_LEN]
    footer = raw[-FOOTER_LEN:]  # preserved exactly (payload_len+mac)

    # decode full encoded section; payload_len is inside footer, but we do not interpret it here
    decoded = affine_decode(encoded)

    # parse payload from the decoded bytes
    track_count, tracks, consumed = parse_payload(decoded)
    original_payload = decoded[:consumed]

    # Apply required modifications
    last_name, non_us_name, longest_time_name, longest_path_name = apply_mods(tracks)

    # Serialize modified payload
    new_payload = serialize_payload(tracks)

    # IMPORTANT: do not change payload length or footer; enforce same length
    if len(new_payload) != len(original_payload):
        raise SystemExit(
            "Refusing to write output: payload length changed.\n"
            f"original payload bytes: {len(original_payload)}\n"
            f"new payload bytes:      {len(new_payload)}\n"
            "This usually means you changed a string to a different byte length.\n"
            "Use same-length replacements (e.g., rename to same UTF-8 length)."
        )

    # Rebuild decoded message: replace payload bytes, keep the rest of decoded bytes (if any) unchanged
    decoded2 = new_payload + decoded[consumed:]

    # Re-encode with affine and preserve footer exactly
    encoded2 = affine_encode(decoded2)
    out = encoded2 + footer

    #open(args.outfile, "wb").write(out)
    open(OUTFILE, "wb").write(out)

    #print("[OK] wrote:", args.outfile)
    print("[OK] wrote:", OUTFILE)
    print("Q1 last alpha drone:", last_name, "-> renamed to Jet Streamer")
    print("Q2 non-US drone:", non_us_name, "-> lat/lon -5 applied")
    print("Q3 longest time drone:", longest_time_name, "-> +3s per segment applied")
    print("Q4 longest path drone:", longest_path_name, "-> points reversed")

if __name__ == "__main__":
    main()
