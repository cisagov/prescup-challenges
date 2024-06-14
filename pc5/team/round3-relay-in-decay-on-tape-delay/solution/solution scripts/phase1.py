
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from scapy.all import *
import time
import sys

# Define the destination IP and port
dest_ip = "10.5.5.x"  # Replace with the destination IP address
dest_port = 55555
# Define the string to send
text_string = sys.argv[1]

# Define the letter-to-value mapping
letter_to_value = {
    'a': 139,
    'b': 64,
    'c': 86,
    'd': 124,
    'e': 93,
    'f': 118,
    'g': 71,
    'h': 45,
    'i': 97,
    'j': 56,
    'k': 87,
    'l': 75,
    'm': 30,
    'n': 102,
    'o': 55,
    'p': 63,
    'q': 35,
    'r': 141,
    's': 83,
    't': 120,
    'u': 134,
    'v': 41,
    'w': 112,
    'x': 68,
    'y': 47,
    'z': 131,

    # Add mappings for other letters as needed
}

# Define the timing between packets (in seconds)
packet_delay = 1

# Create an empty list to store the packets
packets = []

# Craft the packets with the values and append them to the list
for letter in text_string:
    if letter in letter_to_value:
        value = 1.25 * letter_to_value[letter]
        data = f"Signal Value: {value}"
        packet = IP(dst=dest_ip) / TCP(dport=dest_port, sport=RandShort()) / Raw(load=data)
        packets.append(packet)

# Send the packets with the specified timing
for packet in packets:
    send(packet)
    time.sleep(packet_delay)

# Save the packets to a PCAP file
wrpcap("custom_packets.pcap", packets)


