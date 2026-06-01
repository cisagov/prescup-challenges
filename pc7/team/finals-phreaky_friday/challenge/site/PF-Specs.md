# Phreaky Friday – Wire-Level Protocol Specifications (Concise, Spoiler‑Lite)

This document introduces the wire formats used in the challenge. 

Contents:
- [WHPR / “Whisper v1” (UDP framing for byte streams)](#whpr--whisper-v1-udp-framing-for-byte-streams)
- [CLAMSTREAM v1 (masked mini‑frames)](#clamstream-v1-masked-mini-frames)
- [HUSHRTP v1 (nonce handshake + key context)](#hushrtp-v1-nonce-handshake--key-context)
- [T5 “Quartz” LSB Glyph Atlas Transport](#t5-quartz-lsb-glyph-atlas-transport)

---

## WHPR / “Whisper v1” (UDP framing for byte streams)

**Purpose.** Lightweight framing to carry an arbitrary byte stream over UDP. Used in the challenge to ship small binary artifacts (e.g., a WAV) in sequence.

**Link layer.** Standard Ethernet/IPv4/UDP. No special ports are mandated; sample captures often use high ephemeral ports.

**Endianness.** Network byte order (big‑endian) for numeric fields.

### Record Layout (per UDP payload)

```udp
0x00  4  Magic        = "WHPR"            (ASCII)
0x04  2  Seq          = u16 (big‑endian)  monotonic increasing per flow
0x06  2  Len          = u16 (big‑endian)  length of Chunk
0x08  N  Chunk        = Len bytes
```

There is no checksum field; integrity relies on UDP/IP checks and offline validation of the reassembled object.

### Reassembly Guidance
- Group packets by 5‑tuple (src/dst IP, src/dst port, protocol).
- Filter by `data` beginning with `57 48 50 52` (ASCII “WHPR”).
- Sort by **Seq** (wraparound is possible but uncommon in these small sets).
- Concatenate **Chunk** for the target stream.
- The concatenated stream is self‑describing (e.g., a WAV header `RIFF....WAVE...`).

**Notes & Tips**
- Typical chunk sizes are a few hundred bytes (e.g., ~600), chosen to sit well within MTU.
- You can reconstruct the artifact entirely within Wireshark: *Follow UDP Stream* → save the raw bytes from the WHPR direction. Alternatively, script with Scapy/tshark.

---

## CLAMSTREAM v1 (masked mini‑frames)

**Purpose.** Tiny records with a per‑frame XOR “mask” for light obfuscation. Designed to be washable with simple tooling, not cryptographic security.

**Container.** Usually a flat binary file (no pcap). Frames are back‑to‑back; junk may be interleaved.

**Endianness.** N/A except for single‑byte fields.

### Frame Layout (byte‑aligned)

```text
0x00  2  Magic  = "CL"        (ASCII 0x43 0x4C)
0x02  1  Mask   = u8          XOR mask for payload
0x03  1  Len    = u8          payload length in bytes
0x04  L  Data   = Len bytes   masked: Data[i] = Plain[i] ^ Mask
```

**Parsing.** Scan for `0x43 0x4C`. When found, treat next two bytes as `(Mask, Len)`, then read `Len` payload bytes. Advance by `4+Len`. If the magic is not present, advance by 1 (desynchronization recovery).

**Notes & Tips**
- Many frames will decode to printable ASCII after XOR; others may be decoy noise.
- No sequence field: ordering is implied by file position or by higher‑level context.

---

## HUSHRTP v1 (nonce handshake + key context)

**Purpose.** A minimal “handshake” message that surfaces 8‑byte nonces. These nonces serve as inputs to a context‑bound key derivation step used elsewhere in the challenge.

**Link layer.** Standard UDP. There is no strict port assignment; rely on payload inspection.

### Handshake Layout (per UDP payload)

```text
0x00  5  Magic+Kind  = "HUSHR"        (ASCII)
0x05  8  Nonce       = 8‑byte value (opaque)
```

Two handshake messages in a capture form a pair of nonces `(nA, nB)` observed **in capture order**.

### Key Derivation (concept)
A 128‑bit key is derived from `nA || nB` and a short ASCII **context label**. The derivation uses a hash‑based KDF (SHA‑256). Exact label value is part of the challenge context; you’ll encounter it elsewhere in material/hints.

Pseudocode:

```python
digest = SHA256(nA + nB + CONTEXT_LABEL).digest()
key16  = digest[:16]    # 128-bit key material
```

**Notes & Tips**
- Pay attention to the **ordering** of the two nonces (first seen = `nA`, second = `nB`) unless you find evidence otherwise.
- The nonce carried with any subsequent ciphertext (in other files) is **separate** from the handshake nonces.

---

## T5 “Quartz” LSB Glyph Atlas Transport

**Purpose.** Encodes a short string (e.g., an identifier plus a CRC) as indices into a shuffled glyph atlas, masks those indices with a keystream derived from a PNG file, and embeds the masked symbols into the LSBs of a WAV using a hopped, keyed schedule. Bundled as **WAV + PNG**.

Artifacts in the bundle:
- `t5_s1.wav` — stego carrier with LSB payload.
- `t5_glyph.png` — monochrome glyph atlas defining the alphabet order (row‑major).

### Alphabet / Atlas
- Allowed characters: `A–Z`, `0–9`, and `-` (hyphen). Size typically 39.
- The **row‑major order** of the atlas in the PNG defines the mapping *index → character* for this bundle.

### Payload String
The carried string generally follows:

```text
<CORE-TEXT> "-" <BASE32(CRC16_CCITT_FALSE(CORE-TEXT))>
```

The base32 group may be unpadded (no trailing `=`). CRC is computed over ASCII of the core portion.

### Key & Keystream
- A 16‑byte key is derived from **the exact PNG bytes** plus an ASCII context label:
  `key16 = SHA256(png_bytes + CONTEXT_LABEL).digest()[0:16]`
- A bytewise keystream is produced by hashing the key with a monotonically increasing counter and concatenating blocks (i.e., a stream of `SHA256(key || counter)` blocks). This keystream masks each symbol index modulo the alphabet size.

### Embedding (two common modes)
- **Headered (EASY/MEDIUM):** A short header (“T5HDR…”) is written contiguously into LSBs at some start bit. The header includes symbol count, bits‑per‑symbol, hop value, and placement info. Payload bits then follow using a fixed hop.
- **Hard (HARD):** No header. The hop distance for each bit and the **per‑symbol bit order** (big‑ vs little‑endian) are chosen by a RNG seeded from `key16`. The read/write schedule is deterministic but appears pseudo‑random on the wire.

### Bit/Index Conventions
- `bits_per = ceil(log2(alphabet_size))`
- For each symbol value `v`:
  - If **big‑endian** bit order: emit bits from MSB→LSB.
  - If **little‑endian** bit order: emit bits from LSB→MSB.
- Between emitted bits, advance the write index by a **hop** in `[2..7]` (inclusive) when keyed/hard; otherwise by a fixed hop value.

### What’s Fixed vs Variable (per bundle)
- **Fixed by bundle:** PNG (atlas + PNG bytes), WAV (carrier duration), and context labels used for key/keystream.
- **Variable by difficulty:** Presence/absence of header; fixed vs keyed hop; constant vs per‑symbol bit order; start offset selection.

### Interop Notes (for Tooling Authors)
- Treat WAV samples as int16 when extracting LSBs; avoid float round‑trip if you re‑encode.
- Use the **bundle’s PNG file verbatim** to derive `key16`. Re‑saving the PNG will change `key16`.
- If a header isn’t found by scanning, assume keyed/hard mode and reproduce the hop/bit‑order schedule from `key16`.

---

## Appendix A — Example Filters / Pseudocode

**Wireshark display filters**
- Whisper frames (heuristic): `udp && data.len >= 8 && data[0:4] == 57:48:50:52`
- HUSHRTP handshake: `udp && data.len == 13 && data[0:5] == 48:55:53:48:52`

**Scapy snippet (read WHPR chunks)**

```python
from scapy.all import rdpcap, Raw, UDP
buf = bytearray()
for p in rdpcap("t1_whisper_trace.pcap"):
    if UDP in p and Raw in p and p[Raw].load.startswith(b"WHPR"):
        seq  = int.from_bytes(p[Raw].load[4:6], "big")
        leng = int.from_bytes(p[Raw].load[6:8], "big")
        data = p[Raw].load[8:8+leng]
        buf.append((seq, data))
out = b"".join(x[1] for x in sorted(buf))
open("recovered.bin","wb").write(out)
```

**CLAMSTREAM frame walker**

```python
i=0; data=open("t2_clamstream.bin","rb").read()
while i+4 <= len(data):
    if data[i:i+2] == b"CL":
        mask = data[i+2]; L = data[i+3]
        payload = data[i+4:i+4+L]
        plain = bytes(b ^ mask for b in payload)
        # use/collect as needed
        i += 4+L
    else:
        i += 1
```
