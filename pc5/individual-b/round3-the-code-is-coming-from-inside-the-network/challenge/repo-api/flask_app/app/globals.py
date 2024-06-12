
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import random, string

def init():
    global auth_rotate_time
    auth_rotate_time = 3

    global auth_chars
    auth_chars = string.ascii_lowercase+string.ascii_uppercase+string.digits

    global auth_string
    auth_string = ''.join(random.choice(auth_chars) for _ in range(12))

