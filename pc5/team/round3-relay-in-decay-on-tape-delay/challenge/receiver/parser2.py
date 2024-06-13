
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from scapy.all import *
import datetime

# Define the letter-to-value mapping (reverse of your existing mapping)
value_to_letter = {
    139: 'a',
    64: 'b',
    86: 'c',
    124: 'd',
    93: 'e',
    118: 'f',
    71: 'g',
    45: 'h',
    97: 'i',
    56: 'j',
    81: 'k',
    75: 'l',
    30: 'm',
    102: 'n',
    55: 'o',
    63: 'p',
    35: 'q',
    141: 'r',
    83: 's',
    120: 't',
    134: 'u',
    41: 'v',
    112: 'w',
    68: 'x',
    47: 'y',
    131: 'z',
    # Add mappings for other values as needed
}

code_output_file = "/home/user/codes.txt"
value_output_file = "/home/user/values.txt"
with open(code_output_file, "a") as code_file, open(value_output_file, "a") as value_file:
    code_file.write("\n")
    value_file.write("\n")

processed_packets = []
packet_index = 0

# Function to process packets and map values to letters
def process_packet(packet):
    global packet_index
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        data = packet[Raw].load
        try:
            value = float(data.split()[-1])
        except ValueError:
            return "*", None
        adjusted_value = round(value * .6, 2)
        if packet_index % 2 == 1:
            adjusted_value = -adjusted_value
        packet_index += 1
        if adjusted_value in value_to_letter:
            letter = value_to_letter[adjusted_value]
            if packet not in processed_packets:
                processed_packets.append(packet)
                return letter, adjusted_value
        return "*", adjusted_value
    return "*", None

# Sniff incoming packets, process them, and write mapped letters to a file
def main():
    timestamp = datetime.datetime.now().strftime('%d%m%y%H%M')
    with open(value_output_file, "a") as value_file:
    	value_file.write(f"Received at {timestamp}:  ")
    def packet_handler(packet):
        letter, adjusted_value = process_packet(packet)
        if adjusted_value is not None:
            with open(value_output_file, "a") as value_file:
                value_file.write(f"{adjusted_value}, ")
            if letter is not None:
                with open(code_output_file, "a") as code_file:
                    code_file.write(letter)
                print(f"Processed packet: {packet.summary()}. Mapped letter: {letter}.")
        else:
            print(f"Processed packet: {packet.summary()}. Mapped letter: None.")  
    with open(value_output_file, "a") as value_file:
        value_file.write("\n")        


    sniff(iface="eth0", prn=packet_handler, timeout=55, filter="src host 10.20.20.200 and dst port 55555 and tcp")

if __name__ == "__main__":
    main()


