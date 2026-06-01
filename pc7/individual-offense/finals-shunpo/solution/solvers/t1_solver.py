#!/usr/bin/env python3
#####################
# T1 Solver        #
####################
import base64
import gzip
import re
from pathlib import Path

parts = []
for line in Path("artifacts/resolver.log").read_text().splitlines(): # change Path accordingly
    match = re.search(r"qname=(\d{2})([a-z2-7]+)\.telemetry\.kitsune\.internal.*segment=(\d{2})", line)
    if match:
        parts.append((int(match.group(3)), match.group(2)))

encoded = "".join(chunk for _, chunk in sorted(parts))
padding = "=" * ((8 - len(encoded) % 8) % 8)
decoded = base64.b32decode((encoded + padding).upper())
print(gzip.decompress(decoded).decode())