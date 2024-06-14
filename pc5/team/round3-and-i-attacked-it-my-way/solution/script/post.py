#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, requests, sys

def upload_file():
    files = {"login.js":open('login.js','rb')}
    try:
        resp = requests.post("https://10.1.1.74/",data={"api_key":"6fe12e33"},files=files,verify=False)
    except Exception as e:
        print(str(e))
    else:
        print(resp.text)
        print("File Uploaded")

if __name__ == "__main__":
    upload_file()
