#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import zlib

#Read the bytes of the files `type.txt` and `data.txt` in the current `chunk#` folder and then concatenate them.
type_and_data_bytes = bytes()
with open('type.txt','rb+') as f:
    type_and_data_bytes += f.read()
with open('data.txt','rb+') as f:
    type_and_data_bytes += f.read()

# run`zlib.crc32` function on your byte string & alter format
crc_value = zlib.crc32(type_and_data_bytes)
crc_hex = hex(crc_value).replace('0x','')

# CRC is always 8 bytes in length, if it isnt then its smaller and we need to pad it with 0's
if len(crc_hex) != 8:
    missing = 8 - len(crc_hex.replace('0x',''))
    crc_hex = crc_hex.replace('0x',f'0x{0*missing}')

crc_bytes = [f"0x{crc_hex[i:i+2]}" for i in range(0, len(crc_hex),2)]
# convert back to type bytes so that it can be written to file correctly
byte_list = [int(x,16) for x in crc_bytes]
byte_data = bytes(byte_list)

print(byte_data)
