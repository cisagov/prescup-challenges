from pwn import *

elf = ELF("./log-service")

raw = elf.section(".text")
base = elf.get_section_by_name(".text").header.sh_addr

for i in range(0, len(raw)//4):
   offset = i*4
   chunk = raw[offset:offset+4]

   if chunk == b"\xff\xff\xff\xff":
      add = base + offset
      elf.write(add, b'\xe1\xa0\x00\x00')

elf.save("./log-service-clean")
