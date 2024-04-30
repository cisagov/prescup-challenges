#!/usr/img/python3

import zlib, os, sys, subprocess

## HERE: `image_path` is documented as the path to the directory that contains all the `img_#` folders. Currently it is configured to run in the same directory as these folders
image_path = "./"
img_file_dirs = ['img_1','img_2','img_3','img_4','img_5','img_6','img_7','img_8']
chunk_dirs = ['chunk1','chunk2','chunk3']
chunk_files = ['length.txt','type.txt','data.txt']


def determine_crc(cur_bytes):
    crc_value = zlib.crc32(cur_bytes)
    crc_hex = hex(crc_value).replace('0x','')
    if len(crc_hex) != 8:
        missing = 8 - len(crc_hex.replace('0x',''))
        crc_hex = crc_hex.replace('0x',f'0x{0*missing}')
    crc_bytes = [f"0x{crc_hex[i:i+2]}" for i in range(0, len(crc_hex),2)]

    byte_list = [int(x,16) for x in crc_bytes]
    byte_data = bytes(byte_list)

    return byte_data


def read_files():
    for dir in img_file_dirs:
        file_data = None
        with open(f"{dir}/header.txt","rb+") as f:
            file_data = f.read()
        for chunk in chunk_dirs:
            cur_chunk_data = bytes()
            for file in chunk_files:
                cur_file = f"{dir}/{chunk}/{file}"
                with open(cur_file,'rb+') as f:
                    tmp_data = f.read()
                cur_chunk_data += tmp_data
            file_data += cur_chunk_data
            required_crc_data = cur_chunk_data[4:]
            cur_crc = determine_crc(required_crc_data)
            file_data += cur_crc
        with open(f"{dir}.png","wb+") as f:
            f.write(file_data)          


if __name__ == "__main__":
    read_files()
