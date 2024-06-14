#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, subprocess, json

## HERE: this is where you specify the name/path of the corrupted PDF file
file_path = "file.pdf"

def insert(xref_table, xref_order):
    for entry in xref_order:
        obj_data = xref_table[entry]
        current_offset = int(obj_data[0])
        with open(file_path, 'rb+') as f:
            f.seek(current_offset)
            existing_content = f.read()
            f.seek(current_offset)
            for character in entry:
                f.write(character.encode())
            f.write(existing_content)

def get_xref_order(xref_table):
    xref_order = list()
    for key, value in xref_table.items():
        if key == "0 0 obj":
            continue
        if len(xref_order) == 0:
            xref_order.append(key)
            continue
        for cur_index,xref_table_key in enumerate(xref_order):
            if int(value[0]) < int(xref_table[xref_table_key][0]):
                xref_order.insert(cur_index,key)
                break
            elif int(value[0]) > int(xref_table[xref_table_key][0]):
                if xref_table_key == xref_order[-1]:
                    xref_order.append(key)
                    break
                else:
                    continue
    
    insert(xref_table, xref_order)


def set_xref_dict(fp):
    with open(fp,'r',errors='ignore') as f:
        file_lines = f.readlines()
    index = 0
    start_index = 0 
    xref_table = dict()
    while True:
        if 'xref' not in file_lines[index]:
            index += 1
            continue
        else:
            index += 1
            num_objs = file_lines[index].split(' ')[1]
            start_index = index + 1
            break
    xref_lines = file_lines[start_index:start_index+int(num_objs)]
    for obj_num,x in enumerate(xref_lines):

        obj_key = f"{obj_num} 0 obj"
        xref_table[obj_key] = x.strip().split(' ')
    get_xref_order(xref_table)
    

if __name__ == "__main__":
    set_xref_dict(file_path)

