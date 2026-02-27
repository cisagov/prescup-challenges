#!/usr/bin/env python3
"""
Token 2 Unscrambler:
- URL-decodes input
- reverses the string
- fixes Base64 padding
- decodes Base64
"""

import base64
import sys
from urllib.parse import unquote_plus

def fix_padding(s: str) -> str:
    return s + "=" * (-len(s) % 4)

def main():
    if len(sys.argv) > 1:
        raw = sys.argv[1]
    else:
        raw = input("Enter reversed, URL-encoded Base64 > ").strip()

    # 1) URL decode
    decoded = unquote_plus(raw)

    # 2) Reverse
    reversed_b64 = decoded[::-1]

    # 3) Fix padding
    reversed_b64 = fix_padding(reversed_b64)

    try:
        # 4) Base64 decode
        result = base64.b64decode(reversed_b64)
    except Exception as e:
        print(f"[!] Decode failed: {e}")
        sys.exit(1)

    # 5) Print result
    try:
        print(result.decode("utf-8"))
    except UnicodeDecodeError:
        print(result)

if __name__ == "__main__":
    main()