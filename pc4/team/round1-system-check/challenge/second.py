
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from binascii import unhexlify
from getpass import getpass
import hashlib
import os
import sqlite3


def get_flag():
    with sqlite3.connect("local.db") as connection:
        with connection.cursor() as cursor:
            return cursor.execute("SELECT * FROM flag").fetchone()


def lookup_user(username: str):
    with sqlite3.connect("local.db") as connection:
        cursor = connection.cursor()
        result = cursor.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
        cursor.close()
        return result


def main():
    username = input("Please enter your username: ")
    print(f"Welcome, {username}.")
    password = getpass("Please enter your password: ")

    result = lookup_user(username)
    if not result:
        print("That username doesn't exist. Goodbye.")
        return

    username, stored_hash, salt = result

    new_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        unhexlify(salt),
        100000
    )

    if stored_hash != new_hash.hex():
        print("Invalid password.")
    else:
        print(f"Successfully logged in as {username}.")


if __name__ == "__main__":
    main()

