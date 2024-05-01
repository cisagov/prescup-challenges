#!/usr/bin/python3

import subprocess,sys,os,json

def fix_it(pcap_info):
    with open(pcap_info['file'],"rb+") as f:
        file_bytes = f.read()
    # Create object to hold bytes that will be written to create fixed pcap at end
    new_file_bytes = bytes()

    ### first, replace `network` byte value in global header 
    ### corrupted value has wireshark reading traffic as incorrect type 'lin'. This must be corrected.
    new_file_bytes = file_bytes[:20]
    for new_byte in pcap_info['good_network_bytes']:
        new_file_bytes += new_byte

    ### begin looping through data to alter each packet & save to `new_file_bytes` obj
    file_length = len(file_bytes)
    cur_index = 24
    while cur_index < file_length:
        cur_packet = bytes()
        # grab current packet seconds and microseconds bytes.
        cur_packet = file_bytes[cur_index:cur_index+8]

        packet_orignal_length = file_bytes[cur_index+12:cur_index+16]
        correct_packet_capture_length = packet_orignal_length

        cur_packet += correct_packet_capture_length
        
        cur_packet += packet_orignal_length
        packet_data_start_index = cur_index + 16

        hex_str = "0x"
        ### bytes are read and evaluated in reverse bc PCAP file signature indicates file is read in little endian
        for byte in correct_packet_capture_length[::-1]:
            tmp_hex = "0x{:02x}".format(byte)
            hex_str += tmp_hex.replace('0x',"")
        packet_data_num_bytes = int(hex_str,16)
        packet_data_end_index = packet_data_start_index + packet_data_num_bytes
        packet_data = file_bytes[packet_data_start_index:packet_data_end_index]
        cur_packet += packet_data

        new_file_bytes += cur_packet
        cur_index = packet_data_end_index

    with open(f"fixed2.pcap", "wb+") as f:
        f.write(new_file_bytes)
        


if __name__ == "__main__":
    ## To help with tracking values, offsets, and everything else I have stored important information about different parts of the PCAP
    pcap_info = {
        ##### HERE: "file" entry is where you specifiy the name/path of the corrupted PCAP
        "file":"capture.pcap",
        ### Below is correct byte values for the `network` part of global header.This will make it so traffic is read as `ethernet` traffic which is correct.
        "good_network_bytes": [b"\x01",b"\x00",b"\x00",b"\x00"],    
        "global_header": {
            "full_length":24,
            ## list values below are written to represent:  [Number of bytes used to represent its associated part, offset from start of global header to this part]
            "magic":[4,0],
            "major_ver":[2,4],
            "minor_ver":[2,6],
            "zone":[4,8],
            "sigfig":[4,12],
            "snaplen":[4,16],
            "network":[4,20]
        },
        "packet_data": {
            ## list values below are written to represent:  [Number of bytes used to represent its associated part, offset from start of the packet it is a part of]
            "seconds":[4,0],
            "microseconds":[4,4],
            "captured_packet_length":[4,8],
            "original_packet_length":[4,12]
        }
    }
    fix_it(pcap_info)


'''
extra:
#print(file_bytes[20], ' : ',type(file_bytes[20]))

'''