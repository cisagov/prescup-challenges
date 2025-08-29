#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, json, sys, subprocess, os, requests, urllib3

urllib3.disable_warnings()

#####
# NOTE:
# Please read the `grading_README.md` file to get explanation of how the Skills Hub handles grading and requirements needed in your script.
# `sub` variable in each function represents data that was submitted and was passed from server to this script
#   - Could include filename, text entered, multiple choice option chosen, etc.
#####

## This function can be used to run SSH command against remote host and should return any/all relavent information from execution
def runSSHCommand(username=None, password=None, hostname=None, cmdList=None):
    if any(arg is None for arg in [username,password,hostname,cmdList]):
        #print("Error: Function call is missing an argument. Ensure that values are passed for the username, password, hostname, and cmdList")
        return {"error":"Function call missing arguments."}
    elif type(cmdList) != list:
        #print("Error: The commands you want to run should be passed in as a list variable regardless of the number of them")
        return {"error": "Commands passed are not correct data type"}
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, password=password, timeout=10)
    except paramiko.Exception as e:
        ssh.close()
        return {"error": f"Exception occurred while attempting SSH connection. Message: {str(e)}","passed args": f"username: {username}, pwd: {password}, hostname: {hostname}, commands: {cmdList}"}

    results = dict()
    for index,cmd in enumerate(cmdList, start=1):
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

def phase1(sub=None):
    results = dict()
    try:
        resp = requests.get("https://web-mail.skills.hub/api?p=1", verify=False)
        respDict = resp.json()
    except Exception as e:
        print(str(e))

    redirect = False
    file_download = False

    for k,v in respDict.items():
        if 'window.location.href' in v['body']:
            redirect = True
        elif 'fetch(url)' in v['body']:
            file_download = True

    if redirect:      # This is just an example that checks if the data passed (if any) passes the required condition to pass the grading check
        results['GradingCheck1'] = "Success -- Malicious SVG Containing redirect has been sent."
    else:
        results['GradingCheck1'] = "Failure -- Malicious SVG containing redirect has not been sent"

    if file_download:      # This is just an example that checks if the data passed (if any) passes the required condition to pass the grading check
        results['GradingCheck2'] = "Success -- Malicious SVG Containing file download has been sent."
    else:
        results['GradingCheck2'] = "Failure -- Malicious SVG containing file download has not been sent"

    return results


def phase2(sub=None):
    results = dict()

    if sub['GradingCheck3'] == '8443':
        results['GradingCheck3'] = f"Success -- Correct port found."
    else:
        results['GradingCheck3'] = f"Failure -- Incorrect port entered."

    if sub['GradingCheck4'] == 'Pip_Boy111':
        results['GradingCheck4'] = f"Success -- Correct header value found."
    else:
        results['GradingCheck4'] = f"Failure -- Incorrect header value entered."
    
    return results
    

def phase3(sub=None):
    results = dict()

    try:
        resp = requests.get("https://web-mail.skills.hub/api?p=3", verify=False)
        respDict = resp.json()
    except Exception as e:
        print(str(e))

    if respDict['enableJS'] == False:
        results['GradingCheck5'] = f"Success -- JavaScript execution has been disabled."
    else:
        results['GradingCheck5'] = f"Failure -- JavaScript execution has not been disabled."

    return results


if __name__ == '__main__':
    # phases variable should contain list of all phases implemented in the lab & has a function declared above
    phases = ['phase1','phase2','phase3']
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
