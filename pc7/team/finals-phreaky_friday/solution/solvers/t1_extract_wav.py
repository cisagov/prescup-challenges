# reconstruct wav PCAP
from scapy.all import rdpcap, Raw
import sys

PCAP = "t1_whisper_trace.pcap"
OUT  = "t1_calldata_recovered.wav"

def main():
    pkts = rdpcap(PCAP)
    frames = []

    for p in pkts:
        if Raw not in p:
            continue
        raw = bytes(p[Raw].load)
        if not raw.startswith(b"WHPR") or len(raw) < 8:
            continue
        seq  = int.from_bytes(raw[4:6], "big")
        size = int.from_bytes(raw[6:8], "big")
        chunk = raw[8:8+size]
        # basic sanity
        if len(chunk) != size:
            continue
        frames.append((seq, chunk))

    if not frames:
        print("[!] No WHPR frames found.")
        sys.exit(1)

    frames.sort(key=lambda x: x[0])
    blob = b"".join(chunk for _, chunk in frames)

    # Quick RIFF sanity check (optional)
    if not blob.startswith(b"RIFF") or b"WAVE" not in blob[:64]:
        print("[!] Rebuilt blob doesn’t look like RIFF/WAVE yet (continuing anyway).")

    with open(OUT, "wb") as f:
        f.write(blob)

    print(f"[+] Wrote {OUT} ({len(blob)} bytes)")

if __name__ == "__main__":
    main()