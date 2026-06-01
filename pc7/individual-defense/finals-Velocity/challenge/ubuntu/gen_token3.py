#!/usr/bin/env python3
import os, sys

var = "TOKEN3"

s = os.environ.get(var)
if s is None:
    print(f"Missing env var: {var}", file=sys.stderr)
    sys.exit(1)

b = s.encode("utf-8")
hex_bytes = [f"\\x{(x):02x}" for x in b]
n=len(hex_bytes)//8
l=[]
for i in range(n+1):
    if i == n:
        out = '\\x48\\xb8'+''.join(hex_bytes[i*8:])
        l.append(out)
    else:
        out = '\\x48\\xb8'+''.join(hex_bytes[i*8:(i*8)+8])+'\\x50'
        l.append(out)

l.reverse()
d = (40-len(l[0]))//4
l[0] = l[0] + ('\\x00' * d) + '\\x50'
sl=''
for i in range(len(l)):
    if i == len(l)-1: sl = sl + f'"{l[i]}"'
    else: sl = sl + f'"{l[i]}"\n\t'

# Read in the file
f='/tmp/launcher.c'
with open(f, 'r') as file:
  filedata = file.read()

# Replace the target string
filedata = filedata.replace('PLACEHOLDER',sl)

# Write the file out again
with open(f, 'w') as file:
  file.write(filedata)
