#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import subprocess, sys

def shutdownCheck():
    shutdownChk = subprocess.run(f"curl -m 2 123.45.67.100:5050/",shell=True,capture_output=True).stdout.decode('utf-8')
    if "satellite offline" in shutdownChk.lower():
        print('Success')
        print('Token',' : ', 'a83b51ff')
    else:
        print('Failure -- Satellite Online')


if __name__ == '__main__':
    shutdownCheck()
