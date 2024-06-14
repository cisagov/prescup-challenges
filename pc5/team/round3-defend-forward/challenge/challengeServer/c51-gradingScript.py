#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import logging
import subprocess
import sys

logging.info(f"Got args {sys.argv}")
results = {}

attacker1octet1 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f12", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker1octet2 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f15", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker1octet3 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f15", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker1octet4 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f1", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker1=str(attacker1octet1+'.'+attacker1octet2+'.'+attacker1octet3+'.'+attacker1octet4)

attacker2octet1 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f13", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker2octet2 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f16", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker2octet3 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f16", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker2octet4 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f2", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker2=str(attacker2octet1+'.'+attacker2octet2+'.'+attacker2octet3+'.'+attacker2octet4)

attacker3octet1 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f14", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker3octet2 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f17", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker3octet3 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f17", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker3octet4 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f3", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
attacker3=str(attacker3octet1+'.'+attacker3octet2+'.'+attacker3octet3+'.'+attacker3octet4)

password_part1 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.password' | cut -c 1-10", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
password_part2 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.password' | cut -c 11-20", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()
password_part3 = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.password' | cut -c 21-30", shell=True, capture_output=True).stdout.decode('utf-8').strip().lower()

if sys.argv[1].lower().strip() == attacker1:
    results['GradingCheck1'] = "Success -- The first 10 characters of the password is "+password_part1
else:
    results['GradingCheck1'] = "Failure -- This was not the attacker"

if sys.argv[2].lower().strip() == attacker2:
    results['GradingCheck2'] = "Success -- The second 10 characters of the password is "+password_part2
else:
    results['GradingCheck2'] = "Failure -- This was not the attacker"

if sys.argv[3].lower().strip() == attacker3:
    results['GradingCheck3'] = "Success -- The third/final 10 characters of the password is "+password_part3
else:
    results['GradingCheck3'] = "Failure -- This was not the attacker"


for key, value in results.items():
    print(key, ' : ', value)
