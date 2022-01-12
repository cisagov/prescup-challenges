
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import struct

import requests

SERVER_ADDR = "localhost:8000"


def fibonacci(_n):
    if _n < 1:
        raise ValueError("_n must be positive")
    _a, _b = 0, 1
    for _ in range(_n):
        yield _a
        new_b = (_a + _b) % 256
        if new_b > 127:
            new_b = -((new_b ^ 0xFF) + 1)
        _a, _b = _b, new_b

def binary_repr(num):
    return ''.join('{:0>8b}'.format(c) for c in struct.pack('!d', num))

def shift_to_double(position):
    return struct.unpack("!d", (1 << position).to_bytes(8, byteorder="big"))[0]

def main():
    req = requests.get(f"http://{SERVER_ADDR}/first")
    j = req.json()
    given_seq = j["sequence"]
    print(given_seq)
    fib_gen = fibonacci(len(given_seq) + j["resp_len"])
    resp = []
    for _f in range(len(given_seq)):
        next(fib_gen)
    for _f in fib_gen:
        resp.append(_f)
    req = requests.post(f"http://{SERVER_ADDR}/first", json={"sequence": resp})
    print(req.content)

    req = requests.get(f"http://{SERVER_ADDR}/second")
    j = req.json()
    for value in j["sequence"]:
        print(str(value), binary_repr(value))
    resp = []
    for value in range(len(j["sequence"]), len(j["sequence"]) + j["resp_len"]):
        float_value = shift_to_double(value)
        resp.append(str(float_value))
    req = requests.post(f"http://{SERVER_ADDR}/second", json={"sequence": resp})
    print(req.content)

    req = requests.get(f"http://{SERVER_ADDR}/third")
    j = req.json()
    full_set = set(range(256))
    partial_set = set(j["sequence"])
    print(partial_set)
    resp = list(full_set - partial_set)
    req = requests.post(f"http://{SERVER_ADDR}/third", json={"sequence": resp})
    print(req.content)

if __name__ == "__main__":
    main()

