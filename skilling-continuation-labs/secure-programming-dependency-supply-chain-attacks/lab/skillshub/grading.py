#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, json, sys, subprocess, os, requests

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
    results = {}

    ssh_result = runSSHCommand("user", "tartans", "10.5.5.10", ["grep [sS]tole /home/user/Documents/JavaScript/packages/webapptools/index.js"])
    http_result = requests.get("http://10.5.5.5:4873/-/verdaccio/data/packages")

    if "tole" in ssh_result["cmd1"]["stdout"]:
        results["GradingCheck1"] = "Success - index.js has the new line added"
    else:
        results["GradingCheck1"] = "Failure - index.js does not have the new line added"

    if "webapptools" in http_result.text:
        results["GradingCheck2"] = "Success - webapptools is published"
    else:
        results["GradingCheck2"] = "Failure - webapptools is not published"

    return results


def phase2(sub=None):
    results = {}

    ssh_result = runSSHCommand("user", "tartans", "10.5.5.10", ["grep 'Hijacked package' /home/user/Documents/Java/packages/hijacked-secure-utils/src/main/java/com/example/utils/AuthenticationHelper.java"])
    request_body = {
        "action": "coreui_Browse",
        "method": "read",
        "data": [{
            "repositoryName": "maven-public",
            "node": "com/example/secure-utils",
        }],
        "type": "rpc",
        "tid": 10,
    }
    http_result = requests.post("http://10.5.5.5:8081/service/extdirect", json=request_body)

    if "Hijacked package" in ssh_result["cmd1"]["stdout"] and "//" not in ssh_result["cmd1"]["stdout"]:
        results["GradingCheck3"] = "Success - AuthenticationHelper.java has been edited"
    else:
        results["GradingCheck3"] = "Failure - AuthenticationHelper.java has not been edited"

    if "1.3.1" in http_result.text:
        results["GradingCheck4"] = "Success - webapptools is published"
    else:
        results["GradingCheck4"] = "Failure - webapptools is not published"

    return results
    

def phase3(sub=None):
    results = {}

    ssh_result = runSSHCommand("user", "tartans", "10.5.5.10", ["grep bin-proto /home/user/Documents/Rust/apps/demo_app/Cargo.toml"])
    http_result = requests.get("http://10.5.5.5:4200/api/v1/crates/bin-proto")

    if "versions" in http_result.text:
        results["GradingCheck5"] = "Success - bin-proto has been published"
    else:
        results["GradingCheck5"] = "Failure - bin-proto has not been published"

    if "bin-proto" in ssh_result["cmd1"]["stdout"]:
        results["GradingCheck6"] = "Success - bin-proto has been added to the demo_app project"
    else:
        results["GradingCheck6"] = "Failure - bin-proto has not been added to the demo_app project"

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
