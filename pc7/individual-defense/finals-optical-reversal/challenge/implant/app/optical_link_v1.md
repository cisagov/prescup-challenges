# Optical Link v1 (Spec Excerpts)

## Question 1 Link Local
The implant requires a dynamic link-layer handshake before accepting any higher-level commands. To compute the correct value, determine the IPv4 address the implant sees you as using, convert it to network-order bytes, and take the first four bytes of its MD5 hash. XOR each of those four bytes with 0x5A to form the key K, then XOR the ASCII string “OPTO” with K byte-by-byte. Hex-encode the resulting four bytes and supply them using handshake <hex>.

A correct submission establishes the link and reveals TOKEN1.

## Question 2 Control Frame Encoding 

Discover the IPv4 address of `null-horizon.local` and convert it into 4 bytes
in network order (for example, `10.5.5.50` → `0A 05 05 32`).

Compute:

```text
    BASE = (sum(IP bytes) XOR 0xA5) mod 256
```

The control frames are provided as a hex-encoded byte string C (see below).
To recover the plaintext bytes P[i], apply:

```text
    P[i] = C[i] XOR ((BASE + i) mod 256)
```

where:
- i starts at 0 for the first byte,
- arithmetic is done modulo 256,
- the result P is interpreted as UTF-8 text.

### Encoded Control Frames

The encoded control frame blob is (example):

```text
    FRAMES_HEX = afadabadb8a7b9afa5ccbeabbcb1bcb7
```

Decode FRAMES_HEX per the rule above to obtain the plaintext control phrase.
Submit the recovered phrase via:

```text
    frames submit <plaintext>
```
    
## Question 3 (Depends on TOKEN2)
After valid frames are activated, the device emits periodic beacons that leak a token. Detect these beacons in network traffic to determine TOKEN3.

## Question 4 RC4 Artifact 
Retrieve `t4.rc4` (TCP `download rc4`). RC4 key = first 16 bytes of SHA1("opr:" + implant_IPv4_address (no CIDR)).
Decrypt the file; the plaintext equals TOKEN4. NOTE: It has been determined that sometimes the implant falls back to `localhost` or `127.0.0.1` if it cannot reach it's check-in destination.

## Question 5 LFSR Scrambler 
Retrieve `t5.lfsr` (TCP `download lfsr`). Byte i is XOR’d with the next byte from an 8-bit LFSR with polynomial 0xB8 and seed 0xA7. Unscramble to reveal TOKEN5.

## Question 6 Timing Channel
Issue `pulse start` then repeatedly `pulse tick`. Measure server response delay per tick:
~0.10s ⇒ bit 0; ~0.30s ⇒ bit 1 (± small jitter). 8 bits per byte MSB-first. Reconstruct plaintext (TOKEN6).

## Question 7 Finalization 
Send UDP `NONCE` to port 30415. Compute HMAC-SHA256 with key=TOKEN6 and msg=NONCE; submit lowest 8 hex via TCP `finalize <hmac8>` to reveal TOKEN7.
