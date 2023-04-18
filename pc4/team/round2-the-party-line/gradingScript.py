#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import logging
import subprocess
import sys

def grade_challenge():
    '''
    This script can do anything you need to do to grade the grade_challenge.
    This simple example is just a demo
    '''

    results = {}
    passedCurl = False
    passedIRC = False
    passedFTP = False
    
    out4 = subprocess.run('nmap 10.5.5.160 -p 32210', shell=True, capture_output=True)
    #print(out4.stdout.decode('utf-8'))
    
    if  '32210/tcp open' in out4.stdout.decode('utf-8'):
        passedFTP = False
    else:
        passedFTP = True
        
        out2 = subprocess.run('curl http://10.5.5.160', shell=True, capture_output=True)
        #print(out2.stdout.decode('utf-8'))
        
        if '<html' in out2.stdout.decode('utf-8'):
            passedCurl = True
            
            out3 = subprocess.run('nmap 10.5.5.160 -p 6667', shell=True, capture_output=True)
            #print(out3.stdout.decode('utf-8'))

            if '6667/tcp open' in out3.stdout.decode('utf-8').lower():
                passedIRC = True
    
    if passedCurl == True and passedIRC == True and passedFTP == True:
        results['GradingCheck1'] = "Success -- Server remediation was successful!!"
    else:
        results['GradingCheck1'] = "Failure -- The server is not in the correct state. Please try again."
        
    for key, value in results.items():
        print(key, ' : ', value)

if __name__ == '__main__':
    grade_challenge()

