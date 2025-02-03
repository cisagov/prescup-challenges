#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#

from base64 import standard_b64encode as b64encode
from dataclasses import dataclass
import json
import struct
import socket
import sys

# pip install x25519
import x25519


if "--local" in sys.argv:
    SERVER = "localhost"
else:
    SERVER = "challenge.us"

PRIVATE_KEY = b'1' * 32


@dataclass
class Message:
    nonce: bytes | None
    data: bytes


def read_message(conn: socket.socket) -> Message:
    length = struct.unpack(">Q", conn.recv(8))[0]
    msg_buf = conn.recv(length)
    data = json.loads(msg_buf)
    try:
        nonce = bytes(data['nonce'])
    except TypeError:
        nonce = None
    return Message(nonce, bytes(data['data']))


def write_message(conn: socket.socket, msg: Message):
    msg_json = json.dumps(
        {
            "nonce": msg.nonce,
            "data": list(msg.data)
        }
    ).encode()
    length = struct.pack(">Q", len(msg_json))
    conn.send(length)
    conn.send(msg_json)


def negotiate_shared_secret(conn: socket.socket) -> bytes:
    our_pub_key = Message(
        nonce=None,
        data=bytes(
            x25519.scalar_base_mult(PRIVATE_KEY)
        )
    )

    write_message(conn, our_pub_key)
    their_pub_key = read_message(conn)
    shared_secret = x25519.scalar_mult(PRIVATE_KEY, their_pub_key.data)

    return shared_secret


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((SERVER, 23456))
        shared_secret = negotiate_shared_secret(conn)

        # Part 1
        print(b64encode(shared_secret))

        # Part 2
        conn.send(bytes((255, 255, 255, 255, 255, 255, 255, 255)))
        conn.close()


if __name__ == "__main__":
    main()
