#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, subprocess, json

## HERE: this is where you specify the name/path of the corrupted ZIP file
file_path = "var4.zip"

def fix_local_headers(files, local_header_info, current_local_record_offset):
    for file_index in range(len(files)):
        current_file = files[file_index]
        ## get offset of where current local record filename_length 
        file_length_location_offset = current_local_record_offset + local_header_info['filename_length']['offset']
        ## get hex equivalent of length of current filename
        file_length_hex = hex(len(current_file))
        ## instantiate variable that will hold the bytes that will be inserted for the file_length
        file_length_hex_bytes = list()
        ## get offset of where current local record filename
        filename_location_offset = current_local_record_offset + local_header_info['filename']['offset']
        ## instantiate variable that will hold the bytes that will be inserted for the filename
        filename_bytes = list()

        # entry for file length is two bytes, need to ensure correct bytes are inserted based on current file in loop. Dont forget its in little endian.
        if len(file_length_hex.strip('0x')) <= 2:
            file_length_hex_bytes = [bytes([int(f"0x{file_length_hex.strip('0x')}",16)]),b"\x00"]
        elif len(file_length_hex.strip('0x')) == 3:
            first_byte = bytes([int(f"0x0{file_length_hex.strip('0x')[:1]}",16)])
            second_byte = bytes([int(f"0x{file_length_hex.strip('0x')[1:]}",16)])
            file_length_hex_bytes = [first_byte,second_byte]
        else:
            first_byte = bytes([int(f"0x0{file_length_hex.strip('0x')[:2]}",16)])
            second_byte = bytes([int(f"0x{file_length_hex.strip('0x')[2:]}",16)])
            file_length_hex_bytes = [first_byte,second_byte]

        for c in list(current_file):
            hex_equiv = hex(ord(c))
            encoded = bytes([int(hex_equiv,16)])
            filename_bytes.append(encoded)

        for cur_offset, data_to_insert in zip([file_length_location_offset,filename_location_offset],[file_length_hex_bytes,filename_bytes]):
            with open(file_path, 'rb+') as f:
                f.seek(cur_offset)
                existing_content = f.read()
                f.seek(cur_offset)
                for d in data_to_insert:
                    f.write(d)
                f.write(existing_content)
        with open(file_path, 'rb+') as f:
            data = f.read()
        local_sig = b''.join(record_info['local']['signature'])
        current_local_record_offset = data.find(local_sig,filename_location_offset)
        

def fix_central_directory(files,central_dir_info, current_central_start_offset):
    for file_index in range(len(files)):
        current_file = files[file_index]
        filename_bytes = list()
        filename_offset = 0
        ## insert Central directory signature
        with open(file_path, 'rb+') as f:
            f.seek(current_central_start_offset)
            existing_content = f.read()
            f.seek(current_central_start_offset)
            for d in central_dir_info['signature']:
                f.write(d)
            f.write(existing_content)
        
        for c in list(current_file):
            hex_equiv = hex(ord(c))
            encoded = bytes([int(hex_equiv,16)])
            filename_bytes.append(encoded)

        ## Insert filename bytes
        with open(file_path, 'rb+') as f:
            filename_offset = current_central_start_offset + central_dir_info['filename']['offset']
            f.seek(filename_offset)
            existing_content = f.read()
            f.seek(filename_offset)
            for b in filename_bytes:
                f.write(b)
            f.write(existing_content)

        ## find current central directory record comment & document start of next central directory record
        if current_file in list(central_dir_info['comments'].keys()):
            with open(file_path, 'rb+') as f:
                file_data = f.read()
            encoded_comment = central_dir_info['comments'][current_file].encode()
            comment_start_index = file_data.find(encoded_comment)
            current_central_start_offset = comment_start_index + len(central_dir_info['comments'][current_file])

def insert(record_info, local_sig_start_index, central_starting_index):
    files = record_info['filenames']
    local_header_info = record_info['local']
    fix_local_headers(files, local_header_info, local_sig_start_index)
    central_dir_info = record_info['central']
    fix_central_directory(files,central_dir_info, central_starting_index)

def read_zip(record_info):
    with open(file_path,'rb') as f:
        data = f.read()
    local_sig_start_index = None       # Will contain all the offset/index of signatures for the local header records
    central_starting_index = None   # will contain the offset/index of the starting point (first entry) in central directory
    # find all local header records signatures offset/index 
    local_sig = b''.join(record_info['local']['signature'])
    local_sig_start_index = data.find(local_sig)
    # find offset/index for first record in central directory
    end_sig = b''.join(record_info['end_of_central']['signature'])
    end_central_start_index = data.find(end_sig)
    central_offset = end_central_start_index + record_info['end_of_central']['central_start']['offset']
    tmp_list = list()
    for val in range(central_offset, central_offset+4):
        tmp_list.append(hex(data[val]))
    rev_list = tmp_list[::-1]
    while True:
        if '0x0' in rev_list:
            rev_list.remove('0x0')
        else:
            break
    hex_string = '0x'
    for index in range(len(rev_list)):
        cur_hex = rev_list[index][2:] if len(rev_list[index][2:]) == 2 else f"0{rev_list[index][2:]}"
        hex_string += f'{cur_hex}'
    central_starting_index = int(hex_string,16)
    insert(record_info, local_sig_start_index, central_starting_index)
   

if __name__ == "__main__":
    record_info = {
        "filenames": ["joyous","whimsical","bingo","sad"],
        "local": {
            "signature": [b'\x50',b'\x4b',b'\x03',b'\x04'],
            "filename_length": {
                "offset":26,
                "bytes":2
            },
            "filename": {
                "offset":30
            }
        },
        "central":{
            "signature": [b'\x50',b'\x4b',b'\x01',b'\x02'],
            "filename": {
                "offset":46
            },
            "comments": {
                'joyous':'comment: (:',
                'whimsical':'comment: :D',
                'bingo':'comment: winner'
                }
        },
        "end_of_central": {
            "signature": [b'\x50',b'\x4b',b'\x05',b'\x06'],
            "central_start": {
                "offset": 16,
                "bytes":4
            }
        }
    }
    read_zip(record_info)
