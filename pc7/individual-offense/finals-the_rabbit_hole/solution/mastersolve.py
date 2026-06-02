#!/usr/bin/env python3
"""
Usage:
  python3 mastersolve.py --host <challenge_ip> --port 42424
"""
import socket, struct, binascii, time, argparse, sys

KNOWN = b"CTF-CHALLENGE-V1"

# ---------- primitives (same as challenge) ----------
def rol32(x, r):
    return ((x << r) & 0xffffffff) | (x >> (32 - r))
def ror32(x, r):
    return ((x >> r) | ((x << (32 - r)) & 0xffffffff)) & 0xffffffff

def permute_block(v0, v1, rounds=8):
    for i in range(rounds):
        v0 = (v0 + rol32(v1 ^ 0x9e3779b9, (i & 31))) & 0xffffffff
        v1 = (v1 + rol32(v0 ^ 0x7f4a7c15, ((i * 3) & 31))) & 0xffffffff
        v0 ^= (v1 << ((i + 1) & 7)) & 0xffffffff
        v1 ^= ror32(v0, (i & 7))
    return v0 & 0xffffffff, v1 & 0xffffffff

class TinyPRNG:
    def __init__(self, seed_bytes):
        if len(seed_bytes) < 16:
            seed_bytes = seed_bytes.ljust(16, b'\x00')
        self.state = list(struct.unpack("<4I", seed_bytes[:16]))
    def next_u32(self):
        s0, s1, s2, s3 = self.state
        t = (s0 ^ ((s0 << 11) & 0xffffffff)) & 0xffffffff
        s0 = s1; s1 = s2; s2 = s3
        s3 = (s3 ^ (s3 >> 19) ^ (t ^ (t >> 8))) & 0xffffffff
        self.state = [s0,s1,s2,s3]
        return s3
    def keystream(self, nbytes):
        out = bytearray()
        while len(out) < nbytes:
            out += struct.pack("<I", self.next_u32())
        return bytes(out[:nbytes])

def xs_stream_encrypt(plain, seed):
    pr = TinyPRNG(seed)
    ks = pr.keystream(len(plain))
    return bytes([p ^ k for p,k in zip(plain, ks)])

def chain_update(pair_bytes):
    a,b = struct.unpack("<2I", pair_bytes)
    a2,b2 = permute_block(a ^ 0x11111111, b ^ 0x22222222)
    return struct.pack("<2I", a2, b2)

# ---------- GF(2) helpers (same as before) ----------
def set_bit_int(x, i):
    return x | (1 << i)

def gaussian_elim_gf2(rows, ncols):
    rows = rows[:]  # copy
    nrows = len(rows)
    pivot_for_col = [-1] * ncols
    row = 0
    for col in range(ncols):
        sel = -1
        for r in range(row, nrows):
            if ((rows[r] >> col) & 1):
                sel = r; break
        if sel == -1:
            continue
        rows[row], rows[sel] = rows[sel], rows[row]
        pivot_for_col[col] = row
        for r in range(nrows):
            if r != row and ((rows[r] >> col) & 1):
                rows[r] ^= rows[row]
        row += 1
        if row >= nrows:
            break
    for r in range(nrows):
        if (rows[r] & ((1<<ncols)-1)) == 0:
            if ((rows[r] >> ncols) & 1):
                raise RuntimeError("No solution (inconsistent)")
    sol = 0
    for col in range(ncols):
        prow = pivot_for_col[col]
        if prow == -1:
            continue
        bit = (rows[prow] >> ncols) & 1
        if bit:
            sol = set_bit_int(sol, col)
    return sol

# ---------- reconstruct state from keystream ----------
def reconstruct_state_from_keystream(keystream_bytes):
    needed = len(keystream_bytes)
    num_outputs = (needed + 3)//4
    basis_outputs = [bytearray(needed) for _ in range(128)]
    for bit_index in range(128):
        word_idx = bit_index // 32
        bit_in_word = bit_index % 32
        s = [0,0,0,0]; s[word_idx] = (1 << bit_in_word)
        seed = struct.pack("<4I", *s)
        pr = TinyPRNG(seed)
        outb = bytearray()
        for _ in range(num_outputs):
            outb += struct.pack("<I", pr.next_u32())
        outb = outb[:needed]
        basis_outputs[bit_index][:] = outb
    rows = []
    for byte_i in range(needed):
        obs = keystream_bytes[byte_i]
        for bit_in_byte in range(8):
            row_int = 0
            for col in range(128):
                bv = basis_outputs[col][byte_i]
                if ((bv >> bit_in_byte) & 1):
                    row_int = set_bit_int(row_int, col)
            row_int |= (( (obs >> bit_in_byte) & 1) << 128)
            rows.append(row_int)
    if len(rows) < 128:
        raise RuntimeError("Insufficient equations")
    sol_int = gaussian_elim_gf2(rows, 128)
    words = []
    for w in range(4):
        v = 0
        for b in range(32):
            idx = w*32 + b
            if ((sol_int >> idx) & 1):
                v |= (1 << b)
        words.append(v & 0xffffffff)
    return struct.pack("<4I", *words)

# ---------- robust network reads ----------
def recv_all_immediate(sock, initial_timeout=2.0, small_timeout=0.12):
    """
    Read until we get something matching our initial_timeout.
    Then keep polling with a small timeout to fetch any immediately following bytes.
    Return the full decoded string (utf-8 errors ignored).
    """
    sock.settimeout(initial_timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # break once we've seen at least one newline and some data
            if b"\n" in data:
                break
    except socket.timeout:
        pass
    # now aggressively fetch any immediate trailing data
    try:
        sock.settimeout(small_timeout)
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="ignore")

# ---------- main flow ----------
def parse_greeting(banner):
    def find(tag):
        for line in banner.splitlines():
            if line.startswith(tag + ":"):
                return line.split(":",1)[1].strip()
        return None
    return find("CHALLENGE"), find("LEAK"), find("TB"), find("IPH")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=42424)
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    s = socket.socket()
    s.connect((args.host, args.port))
    banner = recv_all_immediate(s, initial_timeout=2.0, small_timeout=0.12)
    print("Greeting:\n", banner)
    ch_hex, leak_hex, tb_hex, ip_hex = parse_greeting(banner)
    if not all([ch_hex, leak_hex, tb_hex, ip_hex]):
        raise SystemExit("Missing CHALLENGE/LEAK/TB/IPH in greeting")

    cipher = bytes.fromhex(ch_hex)
    ks = bytes([c ^ p for c,p in zip(cipher, KNOWN)])
    print("Recovered keystream:", ks.hex())

    print("Reconstructing 128-bit state from observed keystream...")
    seed = reconstruct_state_from_keystream(ks)
    print("Recovered seed:", seed.hex())

    # verify
    pr = TinyPRNG(seed)
    if pr.keystream(len(KNOWN)) != ks:
        print("WARNING: reconstructed seed did not perfectly reproduce keystream")
    else:
        print("Seed verified.")

    # STARTCHAIN
    s.sendall(f"STARTCHAIN {seed.hex()}\n".encode())
    resp = recv_all_immediate(s, initial_timeout=1.5, small_timeout=0.12)
    print("STARTCHAIN response:", resp.strip())
    if "OK:CHAIN-1" not in resp:
        raise SystemExit("STARTCHAIN rejected")

    chain_key = chain_update(seed[:8])
    if args.verbose:
        print("Initial chain_key:", chain_key.hex())

    master = None
    # send only steps 1..4
    for n in range(1,5):
        expected_plain = f"STEP-{n}-PAYLOAD".encode()
        keyseed = chain_key[:8] + chain_key[:8]
        payload = xs_stream_encrypt(expected_plain, keyseed)
        s.sendall(f"STEP {n} {payload.hex()}\n".encode())
        # read fully (catch NEXT and any MASTER sent together)
        resp = recv_all_immediate(s, initial_timeout=1.5, small_timeout=0.12)
        print(f"STEP {n} response:", resp.strip())
        # if MASTER appears in resp, capture and break
        for line in resp.splitlines():
            if line.startswith("MASTER:"):
                master = line.split(":",1)[1].strip()
                break
        if master:
            break
        # otherwise update chain_key as server did
        chain_key = chain_update(chain_key)
        time.sleep(0.02)

    if not master:
        # try one more immediate read (server might still send trailing data)
        extra = recv_all_immediate(s, initial_timeout=0.5, small_timeout=0.12)
        for line in extra.splitlines():
            if line.startswith("MASTER:"):
                master = line.split(":",1)[1].strip()
                break

    if not master:
        raise SystemExit("Did not observe MASTER token from server")

    print("MASTER token:", master)
    # send GETtoken over the same live socket and read the response (give server a short moment)
    s.sendall(f"GETtoken {master}\n".encode())
    # read result robustly
    token_resp = recv_all_immediate(s, initial_timeout=1.5, small_timeout=0.12)
    print("GETtoken response:\n", token_resp.strip())
    s.close()

if __name__ == "__main__":
    main()
