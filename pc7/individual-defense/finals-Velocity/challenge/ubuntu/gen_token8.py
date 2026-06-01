#!/usr/bin/env python3
import os, sys

var = "TOKEN8"

s = os.environ.get(var)
if s is None:
    print(f"Missing env var: {var}", file=sys.stderr)
    sys.exit(1)

out=' '.join(format(ord(x), 'b') for x in s)
print(out,end="")
