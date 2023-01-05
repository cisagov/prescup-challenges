#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import logging
import subprocess
import sys

logging.info(f"Got args {sys.argv}")

ADDRS = [
    ("1.235.189.106", "Addr1"),
    ("58.172.47.117", "Addr2"),
    ("45.104.34.74", "Addr3"),
    ("128.237.119.12", "Addr4"),
    ("152.200.19.77", "Addr5"),
    ("2.69.27.123", "Addr6")
]


def main():
    # args = set(sys.argv[1:])
    args = set(map(lambda s: s.strip(), sys.argv[1:]))

    for addr, check_key in ADDRS:
        if addr in args:
            message = f"{check_key} : Success -- {addr} is one of the expected addresses"
        else:
            message = f"{check_key} : Failure -- Missing address."
        print(message)


if __name__ == "__main__":
    main()
