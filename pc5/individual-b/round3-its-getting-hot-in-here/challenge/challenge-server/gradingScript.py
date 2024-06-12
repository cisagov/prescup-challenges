#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import logging
import subprocess
import sys

def grade_challenge():
    results = {}
    results['GradingCheck1'] = "Failure -- The atmosphere motor controller has not been shut down." 
    results['GradingCheck2'] = "Failure -- The reactors are operating at normal temperatures." 
    results['GradingCheck3'] = "Failure -- You have not removed the required logs." 
    
    try:
        motor_scp_out = subprocess.run(f"scp -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' user@10.2.2.105:/home/user/Documents/motor_complete.txt /home/user/Documents",shell=True, capture_output=True)
        print(motor_scp_out.stdout.decode('utf-8'))
        
        with open("/home/user/Documents/motor_complete.txt") as f:
            content = f.readlines()
            if "motor_shutdown_complete" in content:
                results['GradingCheck1'] = "Success -- The atmosphere motor controller has been shut down!"
            else:
                results['GradingCheck1'] = "Failure -- The atmosphere motor controller has not been shut down."
    except Exception as error:
        print(f"exception - {error}")
        if "No such file or directory" in str(error):
            results['GradingCheck1'] = "Failure -- The atmosphere motor controller has not been shut down."
        else:
            results['GradingCheck1'] = "Failure -- An error occurred during the grading check. The atmosphere motor controller has not been shut down!"
    
    try:
        reactor_scp_out = subprocess.run(f"scp -i /home/user/.ssh/id_rsa -o 'StrictHostKeyChecking=no' user@10.1.1.99:/home/user/Documents/reactor_complete.txt /home/user/Documents",shell=True, capture_output=True)
        print(reactor_scp_out.stdout.decode('utf-8'))
        
        with open("/home/user/Documents/reactor_complete.txt") as f:
            content = f.readlines()
            if "reactor_shutdown_complete" in content:
                results['GradingCheck2'] = "Success -- The reactors have been disabled!"
            else:
                results['GradingCheck2'] = "Failure -- The reactors are operating at normal temperatures." 
    except Exception as error:
        print(f"exception - {error}")
        if "No such file or directory" in str(error):
            results['GradingCheck2'] = "Failure -- The reactors are operating at normal temperatures."
        else:
            results['GradingCheck2'] = "Failure -- An error occurred during the grading check. The reactors are operating at normal temperatures."
    
    try:
        logging_out = subprocess.run('curl http://reactors.merch.codes/home/getlogids', shell=True, capture_output=True)
        print(logging_out.stdout.decode('utf-8'))

        if 'True' in logging_out.stdout.decode('utf-8'):
            results['GradingCheck3'] = "Failure -- Log cleanup failed."
        else:
            results['GradingCheck3'] = "Success -- Log cleanup was succeeded!"       
    except Exception as error:
        print(f"exception - {error}")
        results['GradingCheck3'] = "Failure -- An error occurred during the grading check. You have not removed the required logs."
       
       
    for key, value in results.items():
        print(key, ' : ', value)

if __name__ == '__main__':
    grade_challenge()
