#!/usr/bin/env python3
import os, sys

key = 0x37
var = "TOKEN1"

s = os.environ.get(var)
if s is None:
    print(f"Missing env var: {var}", file=sys.stderr)
    sys.exit(1)

b = s.encode("utf-8")
hex_bytes = [f"0x{(x ^ key):02x}" for x in b]
out=", ".join(hex_bytes)
print(out,end="")
