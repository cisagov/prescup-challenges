#!/usr/bin/env python3
# helper to create secrets for the challenge
import os, sys, secrets

def main():
    out = sys.argv[1] if len(sys.argv)>1 else "./data/secret.bin"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # 32 bytes server secret (keep secret inside the image)
    with open(out, "wb") as f:
        f.write(secrets.token_bytes(32))
    print("wrote", out)

if __name__ == "__main__":
    main()
