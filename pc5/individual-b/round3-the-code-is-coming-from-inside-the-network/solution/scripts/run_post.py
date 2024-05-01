#!/usr/bin/python3

import os, pathlib, requests, itertools, base64,json, subprocess

def upload():
    install_path = '/home/user/Desktop/flask_app/app/main/main.py'
    auth_token = "**Token you reveived from authentication**"
    request_file_dict = dict()
    local_path = "/home/user/Desktop/main.py"
    request_file_dict[install_path] = open(local_path,'rb')
    resp = requests.post("http://10.3.3.53:5000/", files=request_file_dict, headers={"Authorization":auth_token})
    print(resp.text)


if __name__ == '__main__':
    upload()