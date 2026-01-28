#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, json, sys, subprocess, os

#####
# NOTE:
# Please read the `grading_README.md` file to get explanation of how the Skills Hub handles grading and requirements needed in your script.
# `sub` variable in each function represents data that was submitted and was passed from server to this script
#   - Could include filename, text entered, multiple choice option chosen, etc.
#####

def phase1(sub=None):
    results = dict()
    if sub['GradingCheck1'] == 'b':      
        results['GradingCheck1'] = "Success" # -- A benign command using in previous labs is being used."
    else:
        results['GradingCheck1'] = "Failure" # -- Security Advisories often contain examples of malicious commands unsuited for testing."
    return results

def phase2(sub=None):
    results = dict()
    if sub['GradingCheck2'] == 'b':      
        results['GradingCheck2'] = "Success" # -- Fields can be added to help focus on fields of interest within logs."
    else:
        results['GradingCheck2'] = "Failure" # -- Review 'Add field as column'."
    return results


def phase3(sub=None):
    results = dict()
    if sub['GradingCheck3'] == 'b':      
        results['GradingCheck3'] = "Success" # -- They are not included by default, but can be added via a script."
    else:
        results['GradingCheck3'] = "Failure" # -- Sigma rules can be ADDED, but they are not included by default."
    return results

def phase4(sub=None):
    results = dict()
    if sub['GradingCheck4'] == 'c':      
        results['GradingCheck4'] = "Success"
    else:
        results['GradingCheck4'] = "Failure"
    return results

def phase5(sub=None):
    results = dict()

    try:
        completed = subprocess.run(
            ["python3", "/home/user/skillsHub/custom_scripts/check-rule-and-alerts.py"],
            check=True,
            capture_output=True,
            text=True
        )

        output = completed.stdout.strip()

        if "Success" in output:
            results['GradingCheck5'] = f"{output}"
        elif "Failure" in output: 
            results['GradingCheck5'] = f"{output}"
        else:
            results['GradingCheck5'] = f"Error: Unexpected output '{output}'"

    except subprocess.CalledProcessError as e:
        results['GradingCheck5'] = f"Error: Script failed with code {e.returncode}"

    except Exception as e:
        results['GradingCheck5'] = f"Error: {str(e)}"

    return results


def mini_lab(sub=None):
    results = dict()

    try:
        completed = subprocess.run(
            ["python3", "/home/user/skillsHub/custom_scripts/check-rule-and-alerts-miniChallenge.py"],
            check=True,
            capture_output=True,
            text=True
        )

        output = completed.stdout.strip()

        if "Success" in output:
            results['GradingCheck6'] = f"{output}"
        elif "Failure" in output: 
            results['GradingCheck6'] = f"{output}"
        else:
            results['GradingCheck6'] = f"Error: Unexpected output '{output}'"

    except subprocess.CalledProcessError as e:
        results['GradingCheck6'] = f"Error: Script failed with code {e.returncode}"

    except Exception as e:
        results['GradingCheck6'] = f"Error: {str(e)}"

    return results
#    results = dict()
#    results['GradingCheck6'] = "Failure"
#    return results

if __name__ == '__main__':
    # phases variable should contain list of all phases implemented in the lab & has a function declared above
    phases = ['phase1','phase2','phase3','phase4','phase5','mini_lab']
    args = sys.argv[1:]
    if len(args) > 0:
        passed_phase = args[-1].strip().lower()
        if passed_phase in phases:
            ## This code will execute IF phases is enabled & current phase was passed to script.
            args.pop(-1)
            if len(args) != 0:
                ## This code executes if user submitted answer & it was passed to grading script. 
                submissions = json.loads(args[0])
                res = globals()[passed_phase](submissions)
            else:
                # This code executes if no submission made from user
                res = globals()[passed_phase]()
                
            for key,val in res.items():
                print(key, ' : ', val)
        else:
            # This code will execute if phases are disabled BUT there is still a submission from the user. For this example, we will execute all the functions above. 
            submissions = json.loads(args[0])
            res = dict()
            for phase in phases:    
                res.update(globals()[phase](submissions))
                
            for key,val in res.items():
                print(key, ' : ', val)
    else:
        ## This code will execute if no args were passed, which means that phases are disabled & no submissions occur from user
        res = dict()
        for phase in phases:
            res.update(globals()[phase]())

        for key,val in res.items():
            print(key, ' : ', val)
