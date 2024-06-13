
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os
import re
import sys
import subprocess
import uuid
import time
from scapy.all import *

time.sleep(5)

src_mac = (':'.join(re.findall('..', '%012x' % uuid.getnode())))
print(f"{src_mac}")


if len(sys.argv) != 4:
    print("Usage: python replay_capture.py <capture_file> <interface> <new_destination_ip>")
    sys.exit(1)

# Get the capture file, interface, and new destination IP from command-line arguments
capture_file = sys.argv[1]
interface = sys.argv[2]
new_dst_ip = sys.argv[3]

# Load the captured packets from the provided PCAP file
packets = rdpcap(capture_file)

# Use the 'arp -a' command to retrieve ARP cache information
subprocess.call(["ping", "-c", "1", new_dst_ip])
arp_cache = os.popen('arp -a').read()

# Extract the MAC address from the ARP cache
mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
dst_mac = None

for line in arp_cache.split('\n'):
    if new_dst_ip in line:
        match = mac_pattern.search(line)
        if match:
            dst_mac = match.group(0)
        break

if not dst_mac:
    print("No valid MAC address found for the new destination IP.")
    sys.exit(1)

print(f"{dst_mac}")

# output_pcap_file = "test-out.pcapng"

# Loop through the captured packets and send them to the specified interface
for packet in packets:
    if IP in packet:
        packet[IP].dst = new_dst_ip
        packet[IP].src = '10.10.10.100'
    # Set the destination MAC address in the Ethernet frame
    packet[Ether].dst = dst_mac
    packet[Ether].src = src_mac
    # Send the modified packet out through the specified interface
    sendp(packet, iface=interface)

    # wrpcap(output_pcap_file, packet, append=True)


