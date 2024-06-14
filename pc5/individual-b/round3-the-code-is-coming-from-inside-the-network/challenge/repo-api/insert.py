#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, sqlite3, io
from sqlite3 import *


def upload_file():
    try:
        conn = sqlite3.connect('/home/user/Desktop/flask_app/app.db')
        cursor = conn.cursor()
        fn = "test.py"
        fp = "/home/user/Desktop/flask_app/app/main/static/source/test.py"
        f = io.FileIO(fp)
        fb = io.BufferedReader(f)
        fileBytes = fb.read()

        cmd = f'''insert into Source(name,blob) values (?, ?)'''
        data_tuple = (fn, fileBytes)
        cursor.execute(cmd, data_tuple)
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"error: {e}")
    else:
        print('File uploaded')

def insert_token(tokens):
    for index, tok in enumerate(tokens,1):
        name = f"t{index}"
        cur_tok = tok.strip('\n')
        try:
            conn = sqlite3.connect('/home/user/Desktop/flask_app/app.db')
            cursor = conn.cursor()
            cmd = f'''insert into Token(name,hex) values (?, ?)'''
            data_tuple = (name,cur_tok)
            cursor.execute(cmd, data_tuple)
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"error: {e}")
        else:
            print('File uploaded')

if __name__ == '__main__':
    args = sys.argv[1:]
    insert_token(args)
