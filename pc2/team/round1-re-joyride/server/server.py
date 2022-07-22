#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

KEY = bytes([183, 35, 145, 218, 0, 140, 24, 84, 93, 93, 184, 49, 247, 93, 34, 139])
# We're not really worried about security here beyond making external packet sniffing harder.
# Just reuse it.
IV = bytes([85, 161, 28, 105, 92, 130, 6, 57, 239, 214, 234, 2, 174, 227, 72, 159])


import queue
import random
import socket
import string
import subprocess
import threading
import time

from Crypto.Cipher import AES


FLAGS = []
FLAGS.append('ad40e23fc8b60919')
FLAGS.append('a10f1db5e81b6c15')
FLAGS.append('cb5cb1369bd7f277')
FLAGS.append('3e7a878c3cf8bb81')

ALPHANUMERIC = string.ascii_lowercase + string.ascii_uppercase + string.digits

def get_variant():
    # Modified for open-sourcing.
    #try:
    #    return int(subprocess.run('vmtoolsd --cmd "info-get guestinfo.variant"', shell=True, stdout=subprocess.PIPE).stdout)
    #except Exception as e:
    #    print(e)
    return 1

def generate_ascii(min_size, max_size):
    size = random.randrange(min_size, max_size)
    out_bytes = b''
    for _ in range(size):
        out_bytes += random.choice(ALPHANUMERIC).encode('ascii')

    return out_bytes

def handle_client(client, send_flag):
    client.settimeout(1.0)
    while True:
        try:
            incoming = client.recv(4096)
        except socket.timeout:
            client.shutdown(socket.SHUT_RDWR)
            client.close()
            return
        if len(incoming) == 0:
            break

    if send_flag:
        variant = get_variant()
        flag = FLAGS[variant - 1]
        plaintext = f'prescup{{{flag}}}'.encode('ascii')
    else:
        # Client does this, so make the traffic look similar.
        plaintext = generate_ascii(256, 512)

    crypt_obj = AES.new(KEY, AES.MODE_CBC, IV)
    padding = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding]) * padding
    ciphertext = crypt_obj.encrypt(plaintext)

    try:
        client.sendall(ciphertext)
    except Exception:
        pass
    finally:
        client.shutdown(socket.SHUT_RDWR)
        client.close()

def client_handler_thread(queue_obj):
    flag_counter = 1
    while True:
        client = queue_obj.get()
        try:
            if flag_counter % 200 == 0:
                handle_client(client, True)
            else:
                handle_client(client, False)
        except Exception:
            continue
        flag_counter += 1

def listening_thread(queue_obj):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 5432))
    s.listen(5)

    while True:
        (client, _) = s.accept()
        queue_obj.put(client)

def main():
    client_queue = queue.Queue()

    client_thread = threading.Thread(target=client_handler_thread, args=(client_queue,), daemon=True)
    client_thread.start()

    server_thread = threading.Thread(target=listening_thread, args=(client_queue,), daemon=True)
    server_thread.start()

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            exit(0)

if __name__ == '__main__':
    main()

