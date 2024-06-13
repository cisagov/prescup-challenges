#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import logging
import sys
import subprocess

logging.info(f"Got args {sys.argv}")
results = {}

username = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.username'", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
password = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.password'", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()


if sys.argv[1].lower().strip() == password:
    results['GradingCheck1'] = "Success -- You entered the password that was leaked"
else:
    results['GradingCheck1'] = "Failure -- You did not enter the correct leaked password"

if sys.argv[2] == username:
    results['GradingCheck2'] = "Success -- You entered the correct username of the malware creator"
else:
    results['GradingCheck2'] = "Failure -- You did not enter the correct username of the malware creator"

for key, value in results.items():
    print(key, ' : ', value)
