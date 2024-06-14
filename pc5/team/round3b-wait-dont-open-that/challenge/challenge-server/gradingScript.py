#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import logging
import subprocess
import sys
import os

def grade_token1():
    part1 = "e15d"
    part2 = subprocess.run("vmware-rpctool 'info-get guestinfo.part2'",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')
    part3 = subprocess.run("vmware-rpctool 'info-get guestinfo.part3'",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')
    if sys.argv[1].lower() == str(part1).lower() + str(part2).lower() + str(part3).lower():
        return True
    else:
        return False
                        
def grade_token2():
    part4 = subprocess.run("vmware-rpctool 'info-get guestinfo.part4'",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')
    part5 = "5150OU811984"
    if sys.argv[2].lower() == str(part4).lower() + str(part5).lower():
        return True
    else:
        return False    
                                                
def grade_challenge():
    logging.info(f"Got args {sys.argv}")           
    results = {}
       
    if grade_token1():                                                                 
    	results['GradingCheck1'] = "Success -- you submitted the correct values for parts 1, 2 and 3."
    else: 
    	results['GradingCheck1'] = "Fail -- you submitted incorrect values for parts 1, 2 and 3."
    
    if grade_token2():
    	results['GradingCheck2'] = "Success -- you submitted the correct values for parts 4 and 5."  
    else: 
    	results['GradingCheck2'] = "Fail -- you submitted incorrect values for parts 4 and 5."
        
    for key, value in results.items():
        print(key, ' : ', value)
            
if __name__ == '__main__':
    grade_challenge()
                
                
