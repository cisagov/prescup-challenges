#!/usr/bin/python3

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
