#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, json, sys, subprocess, os

#####
# NOTE:
# Please read the `grading_README.md` file to get explanation of how the Skills Hub handles grading 
# and requirements needed in your script.
#####

def runSSHCommand(username=None, password=None, hostname=None, cmdList=None):
    if any(arg is None for arg in [username,password,hostname,cmdList]):
        print("Function call is missing an argument. Ensure that values are passed for the username, password, hostname, and cmdList")
        return {"error":"Function call missing arguments."}
    elif type(cmdList) != list:
        print("The commands you want to run should be passed in as a list variable regardless of the number of them")
        return {"error": "Commands passed are not correct data type"}
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, password=password, timeout=10)
    except paramiko.Exception as e:
        ssh.close()
        return {"error": f"Exception occurred while attempting SSH connection. Message: {str(e)}","passed args": f"username: {username}, pwd: {password}, hostname: {hostname}, commands: {cmdList}"}

    results = dict()
    for index,cmd in enumerate(cmdList):
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
            results[f'cmd{index}'] = {
                "commandExecute":cmd,
                "stdout":stdout.read().decode().strip(),
                "stderr":stderr.read().decode().strip()
            }
        except Exception as e:
            results[f"cmd{index}"] = {
                "commandExecute":cmd,
                "stdout":"",
                "stderr":f"Error occurred during command execution.\error msg:\t{str(e)}"
            }
    ssh.close()
    return results


# 'sub' variable represents submitted data that was passed from server to this script
def phase1(sub=None):
    results = dict()
    if sub is None:
        sub = {}

    sub = {k: v.lower() if isinstance(v, str) else v for k, v in sub.items()}

    if sub['GradingCheck1'] == 'a':
        results['GradingCheck1'] = "Success"
    else:
        results['GradingCheck1'] = "Failure"
    if sub['GradingCheck2'] == 'b':
        results['GradingCheck2'] = "Success"
    else: 
        results['GradingCheck2'] = "Failure"
    return results


def phase2(sub=None):
    results = dict()
    if sub is None:
        sub = {}

    sub = {k: v.lower() if isinstance(v, str) else v for k, v in sub.items()}

    if sub['GradingCheck3'] == 'c':
        results['GradingCheck3'] = "Success"
    else:
        results['GradingCheck3'] = "Failure"
    if sub['GradingCheck4'] == 'd':
        results['GradingCheck4'] = "Success"
    else: 
        results['GradingCheck4'] = "Failure"
    return results
    

def phase3(sub=None):
    results = dict()

    try:
        completed = subprocess.run(
            ["python3", "/home/user/skillsHub/custom_scripts/check-agent-policy.py"],
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


    try:
        completed = subprocess.run(
            ["python3", "/home/user/skillsHub/custom_scripts/check-ilm-policy.py"],
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


def mini_lab(sub=None):
    results = dict()

    try:
        completed = subprocess.run(
            ["python3", "/home/user/skillsHub/custom_scripts/mini-check-agent-policy.py"],
            check=True,
            capture_output=True,
            text=True
        )

        output = completed.stdout.strip()

        if "Success" in output:
            results['GradingCheck7'] = f"{output}"
        elif "Failure" in output:
            results['GradingCheck7'] = f"{output}"
        else:
            results['GradingCheck7'] = f"Error: Unexpected output '{output}'"

    except subprocess.CalledProcessError as e:
        results['GradingCheck7'] = f"Error: Script failed with code {e.returncode}"

    except Exception as e: 
        results['GradingCheck7'] = f"Error: {str(e)}"

    try:
        completed = subprocess.run(
            ["python3", "/home/user/skillsHub/custom_scripts/mini-check-ilm-policy.py"],
            check=True,
            capture_output=True,
            text=True
        )

        output = completed.stdout.strip()

        if "Success" in output:
            results['GradingCheck8'] = f"{output}"
        elif "Failure" in output:
            results['GradingCheck8'] = f"{output}"
        else:
            results['GradingCheck8'] = f"Error: Unexpected output '{output}'"

    except subprocess.CalledProcessError as e:
        results['GradingCheck8'] = f"Error: Script failed with code {e.returncode}"

    except Exception as e: 
        results['GradingCheck8'] = f"Error: {str(e)}"

    return results


if __name__ == '__main__':
    # phases variable should contain list of all phases implemented in the lab & has a function declared above
    phases = ['phase1','phase2','phase3', 'mini_lab']
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
