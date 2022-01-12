
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import socket


RESET_CODE = b'\1'
START_CODE = b'\2'
SUBMIT_CODE = b'\4'

VALUEPAIR_RESP = b'\0\0\0\0'
RESETACK_RESP = b'\1\1\1\1'
TIMEOUT_RESP = b'\2\2\2\2'
NOTSTARTED_RESP = b'\3\3\3\3'
INCORRECT_RESP = b'\4\4\4\4'
FLAG_RESP = b'\5\5\5\5'
NEEDSRESET_RESP = b'\6\6\6\6'
INVALIDCODE_RESP = b'\255\255\255\255'

SERVER_ADDR = 'localhost'
SERVER_PORT = 12345

MAX_U32 = 2**32


def construct_reset():
    return RESET_CODE


def construct_start():
    return START_CODE


def construct_submit(value):
    return SUBMIT_CODE + value.to_bytes(4, byteorder='little')


def unpack_values(in_bytes):
    if len(in_bytes) != 8:
        raise ValueError(f'Incoming bytes length was not 8: {in_bytes}')
    v1 = int.from_bytes(in_bytes[:4], byteorder='little')
    v2 = int.from_bytes(in_bytes[4:], byteorder='little')
    return v1, v2


def server_request(out_bytes):
    s = socket.create_connection((SERVER_ADDR, SERVER_PORT))
    s.sendall(out_bytes)
    s.shutdown(socket.SHUT_WR)

    in_bytes = b''
    while True:
        new_bytes = s.recv(4096)
        if not new_bytes:
            break
        in_bytes += new_bytes

    s.close()

    return in_bytes


def main():
    resp = server_request(construct_start())
    if not resp[:4] == VALUEPAIR_RESP:
        print(f'Server did not return a ValuePair response: {resp}')
        exit()
    v1, v2 = unpack_values(resp[4:])
    v3 = v1 * v2 % MAX_U32
    print(f'v1: {v1}, v2: {v2}, v3: {v3}')

    while True:
        resp = server_request(construct_submit(v3))
        if resp[:4] == FLAG_RESP:
            print(resp[4:].decode())
            break
        if not resp[:4] == VALUEPAIR_RESP:
            print(f'Server did not return a ValuePair response: {resp}')
            exit()
        v1, v2 = unpack_values(resp[4:])
        v3 = v1 * v2 % MAX_U32
        print(f'v1: {v1}, v2: {v2}, v3: {v3}')


if __name__ == '__main__':
    main()

