#!/usr/bin/env python3

#affine_keys.py

import sys
import math

MOD = 256

def parse(x):
    # Accept hex or decimal
    return int(x, 0)

def modinv(a, m):
    # modular inverse
    try:
        return pow(a, -1, m)
    except ValueError:
        return None

def main():
    if len(sys.argv) != 5:
        print("Usage: ./affine_keys.py c1 c2 p1 p2")
        print("c = ciphertext, p = plaintext")
        sys.exit(1)

    c1 = parse(sys.argv[1])
    c2 = parse(sys.argv[2])
    p1 = parse(sys.argv[3])
    p2 = parse(sys.argv[4])

    dp = (p2 - p1) % MOD
    dc = (c2 - c1) % MOD

    inv_dp = modinv(dp, MOD)
    if inv_dp is None:
        print("Error: dp has no inverse mod 256 (must be odd).")
        sys.exit(1)

    # Solve for a
    a = (dc * inv_dp) % MOD
    print(f"a = {a} (0x{a:02x})")

    # Compute modular inverse of a
    a_inv = modinv(a, MOD)
    if a_inv is None:
        print("Error: a has no inverse mod 256 (invalid affine multiplier).")
        sys.exit(1)

    #print(f"a_inv = {a_inv} (0x{a_inv:02x})")

    # Solve for b using c = a*p + b
    b = (c1 - a * p1) % MOD
    print(f"b = {b} (0x{b:02x})")

if __name__ == "__main__":
    main()
