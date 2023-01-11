#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import subprocess, random, time, os, sys, sqlite3, datetime
import io
from werkzeug.security import generate_password_hash
from sqlite3 import *

def create(args):
    try:
        conn = sqlite3.connect('./adminSite/db.site')
        cursor = conn.cursor()
        uploaded = datetime.datetime.today().strftime('%m-%d-%Y, %H:%M')
        cmd = f'''insert into User(username,password,created) values (?, ?, ?)'''
        data_tuple = (args[0],generate_password_hash(args[1]),uploaded)
        cursor.execute(cmd, data_tuple)
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print('error',':',e)
    else:
        print('user created')

if __name__ == '__main__':
    args = sys.argv[1:]
    create(args)
