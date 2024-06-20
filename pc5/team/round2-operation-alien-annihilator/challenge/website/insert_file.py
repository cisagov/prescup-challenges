#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, random, time, os, sys, sqlite3, datetime, requests, io, json
from sqlite3 import *
from werkzeug.security import generate_password_hash


def upload_file(un, id):
    try:
        conn = sqlite3.connect('/home/user/Desktop/website/site.db')
        cursor = conn.cursor()
        fn = "future_plans.txt"
        fp = "/home/user/Desktop/future_plans.txt"
        f = io.FileIO(fp)
        fb = io.BufferedReader(f)
        fileBytes = fb.read()

        uploaded = datetime.datetime(2023,7,6,13,23).strftime('%m-%d-%Y, %H:%M')
        cmd = f'''insert into File(name,user_username,user_id,role,blob,uploaded) values (?, ?, ?, ?, ?, ?)'''
        data_tuple = (fn, un, id, 'system_user', fileBytes, uploaded)
        cursor.execute(cmd, data_tuple)
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"error: {e}")
    else:
        print('File uploaded')

def create_user(email):
    un = email.split('@',1)[0]
    plaintext_pwd = email+str(random.randint(0,9))
    pwd = generate_password_hash(plaintext_pwd, method='sha1')
    with open("/home/user/Desktop/created_user_data","w+") as f:
        f.write(f"Email:\t {email}\n")
        f.write(f"plaintext password:\t {plaintext_pwd}\n")
        f.write(f"SHA1 hash of password:\t {pwd}")
    new_user = {
        "email":email,
        "username":un,
        "password":pwd,
    }
    url = "https://chat.merch.codes/api/v4/users"
    out = requests.post(url,json=new_user,headers={"Content-Type":"application/json"})
    new_user_dict = json.loads(out.text)
    upload_file(new_user_dict['un'], new_user_dict['id'])


if __name__ == '__main__':
    args = sys.argv
    un = args[1]
    id = args[2]
    upload_file(un,id)
