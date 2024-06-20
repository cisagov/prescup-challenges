
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from enum import Enum
from os import urandom
from socket import socket
from struct import pack, unpack
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


if "--local" in sys.argv:
    SERVER_ADDR = "localhost"
else:
    print("Use '--local' to test this script with a locally-hosted server.")
    SERVER_ADDR = "10.5.5.5"
print(f"Using {SERVER_ADDR} as server address.")

USERNAME = "chris_p_bacon"
# This is the default contents of the `src/token1` file.
# Replace this string with the actual password found for Question 1.
PASSWORD = "Token 1 could not be retrieved. Please contact support."
KEY = b"hello this is 16"

MESSAGE_HEADER_LEN = 4
MESSAGE_HEADER_FMT = "!i"
NONCE_LENGTH = 12


class Mode(Enum):
    Encrypt = 0
    Decrypt = 1


class InvalidMode(Exception):
    ...


class InvalidNonce(Exception):
    ...


def aes(nonce: bytearray(NONCE_LENGTH), data: bytes, mode: Mode) -> bytes:
    aes_gcm = AESGCM(KEY)

    if mode == Mode.Encrypt:
        new_nonce = urandom(NONCE_LENGTH)
        for i in range(NONCE_LENGTH):
            nonce[i] = new_nonce[i]

    elif len(nonce) != NONCE_LENGTH:
        raise InvalidNonce

    match mode:
        case Mode.Encrypt:
            return aes_gcm.encrypt(nonce, data, None)
        case Mode.Decrypt:
            return aes_gcm.decrypt(nonce, data, None)
        case _:
            raise InvalidMode


class MessageLength(Exception):
    ...


class InvalidMessage(Exception):
    ...


def read_message(reader: socket) -> str:
    msg_len_bytes = reader.recv(MESSAGE_HEADER_LEN)
    msg_len = unpack(MESSAGE_HEADER_FMT, msg_len_bytes)[0]

    if msg_len == 0:
        raise MessageLength

    nonce_bytes = reader.recv(NONCE_LENGTH)
    message_bytes = reader.recv(msg_len)

    decrypted_message = aes(nonce_bytes, message_bytes, Mode.Decrypt)
    result = decrypted_message.decode("utf-8")
    if not result.isascii():
        print(result)
        raise InvalidMessage

    return result


def write_message(writer: socket, message: str):
    nonce_bytes = bytearray(NONCE_LENGTH)
    encrypted_message = aes(nonce_bytes, message.encode("utf-8"), Mode.Encrypt)

    msg_len_bytes = pack(MESSAGE_HEADER_FMT, len(encrypted_message))

    writer.sendall(msg_len_bytes)
    writer.sendall(nonce_bytes)
    writer.sendall(encrypted_message)


def handle_login(s: socket):
    write_message(s, USERNAME)
    write_message(s, PASSWORD)

    print(read_message(s))


def handle_knock_knock(s: socket):
    write_message(s, "knock knock")

    print(read_message(s))


def handle_single_challenge(s: socket):
    operation_str = read_message(s)

    try:
        op_1, operation, op_2 = operation_str.split()
    except ValueError as e:
        print(f"Could not split server math challenge: {operation_str}")
        raise e

    try:
        op_1, op_2 = int(op_1), int(op_2)
    except ValueError as e:
        print(f"Could not parse operands into ints: {op_1} {op_2}")
        raise e

    match operation:
        case "+":
            result = op_1 + op_2
        case "-":
            result = op_1 - op_2
        case "*":
            result = op_1 * op_2
        case "/":
            result = op_1 // op_2
        case _:
            msg = f"Could not parse operator: {operation}"
            print(msg)
            raise ValueError(msg)

    write_message(s, str(result))


def handle_math_challenges(s: socket):
    for _ in range(30):
        handle_single_challenge(s)

    write_message(s, "one more")

    handle_single_challenge(s)

    print(read_message(s))


if __name__ == "__main__":
    client = socket()
    client.connect((SERVER_ADDR, 23456))

    handle_login(client)

    # Solve Question 2.
    handle_knock_knock(client)

    # Solve Question 3.
    handle_math_challenges(client)

    client.close()

