#!/usr/bin/env python3
import os, sys

var = "TOKEN5"

s = os.environ.get(var)
if s is None:
    print(f"Missing env var: {var}", file=sys.stderr)
    sys.exit(1)

b = s.encode("utf-8")

s1=s.encode('ascii')[0:10].hex()
s2=s.encode('ascii')[10:].hex()
print(s1)
print(s2)
