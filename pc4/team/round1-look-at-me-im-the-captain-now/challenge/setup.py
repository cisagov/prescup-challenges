#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import subprocess, secrets, random

# configure the zip file with password
def zip(flag, pwd):
    subprocess.run(f"sudo echo {flag} > flag.txt",shell=True,capture_output=True)
    subprocess.run(f"sudo zip -j -P {pwd} ZIP-file.zip flag.txt",shell=True, capture_output=True)

# generate random variables
def setup():
    tmp = secrets.token_hex(8)
    pwd = random.choice("REMS960", "RC2612", "FDR6746", "PGT960", "US3174", "W960", "FC3174", "M3174", "SP960", "R6746")
    zip(tmp,pwd)
    
if __name__=='__main__':
    setup()
    
