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

    cmds = [
        "echo 'aaaaaaaaaaa' | Desktop/buffer_overflow/c_overflow/old_buffer_overflow",
        "cd Desktop/buffer_overflow/rs_safe/ && echo 'aaaaaaaaaaaaaaa' | cargo run"
    ]

    res1 = runSSHCommand('user', 'tartans', 'ubuntu-desktop', [cmds[0]])
    res2 = runSSHCommand('user', 'tartans', 'kali', [cmds[1]])

    if "stack smashing" in res1['cmd1']['stderr']:
        results['GradingCheck1'] = "Success -- Buffer overflow detected during execution"
    else:
        results['GradingCheck1'] = "Failure -- C program did not run correctly."

    if 'Access denied' in res2['cmd1']['stdout']:      # This is just an example that checks if the data passed (if any) passes the required condition to pass the grading check
        results['GradingCheck2'] = "Success -- Rust program executed correctly."
    else:
        results['GradingCheck2'] = "Failure -- Rust program did not execute correctly."

    return results


def phase2(sub=None):
    results = dict()

    cmds = [
        "Desktop/integer_overflow/c_overflow/pointer_offset",
        "cd Desktop/integer_overflow/rs_checked/ && cargo run"
    ]

    res = runSSHCommand('user', 'tartans', 'kali', cmds)

    if 'second entry' in res['cmd1']['stdout']:
        results['GradingCheck3'] = "Success -- C pointer program executed correctly."
    else:
        results['GradingCheck3'] = "Failure -- C pointer program did not execute correctly."


    if 'Int overflow detected' in res['cmd2']['stdout']:
        results['GradingCheck4'] = "Success -- Rust program caught integer overflow."
    else:
        results['GradingCheck4'] = "Failure -- Rust program gave unexpected output or did not handle integer overflow."

    return results
    

def phase3(sub=None):
    results = dict()
    solveChk = 0
    cmds = [
        "Desktop/use_after_free/c_uaf/cleanup_uaf",
        "cd Desktop/use_after_free/rs_safe/ && cargo run"
    ]

    res = runSSHCommand('user', 'tartans', 'kali', cmds)

    if "'free' function is: 0" in res['cmd1']['stdout']:
        results['GradingCheck5'] = "Success -- Vulnerable C program has been cleaned up and use after free bug is mitigated."
        solveChk += 1
    else:
        results['GradingCheck5'] = "Failure -- C program did not execute correctly."

    if ": 10" in res['cmd2']['stdout']:
        results['GradingCheck6'] = "Success -- Rust program runs correctly."
        solveChk += 1
    else:
        results['GradingCheck6'] = "Failure -- Rust program gave unexpected output or did execute correctly."

    if solveChk == 2:
        os.system("cp -r /home/user/skillsHub/challenge /home/user/skillsHub/hosted_files")

    return results


def mini_lab(sub=None):
    results = dict()

    if sub['GradingCheck7'] == 'b':
        results['GradingCheck7'] = "Success -- Correct option chosen."
    else:
        results['GradingCheck7'] = "Failure -- Wrong answer."

    if sub['GradingCheck8'] == 'c':
        results['GradingCheck8'] = "Success -- Correct option chosen."
    else:
        results['GradingCheck8'] = "Failure -- Wrong answer."

    if sub['GradingCheck9'] == 'c':
        results['GradingCheck9'] = "Success -- Correct option chosen."
    else:
        results['GradingCheck9'] = "Failure -- Wrong answer."

    if sub['GradingCheck10'] == 'b':
        results['GradingCheck10'] = "Success -- Correct option chosen."
    else:
        results['GradingCheck10'] = "Failure -- Wrong answer."

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
