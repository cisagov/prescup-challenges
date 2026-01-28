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

data = {
        "phase1": {
            "buffer_resp": "Access granted!",
            "integer_resp":"<0"
        },
        "phase2": {
            "buffer_resp": "Access denied.",
            "integer_resp":"Too many tickets"
        },
        "mini_lab": {}
    }

def phase1(sub=None):
    results = dict()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('kali.hub',username='user',password='tartans',timeout=10)
    except paramiko.Exception as e:
        #print(str(e))
        results['GradingCheck1'] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
        results['GradingCheck2'] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
        ssh.close()
        return results
    
    ## Start grading checks on C Programs
    cmds = ['echo "aaaaaaaaaaaa" | ./Desktop/buffer_vuln', 'echo "999999999999999" | ./Desktop/integer_vuln']

    ## Grade buffer overflow C program
    try:
        stdin, stdout, stderr = ssh.exec_command(cmds[0], timeout=5)
        buf_resp = stdout.read().decode().strip()
    except Exception as e:
        results['GradingCheck1'] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
    else:
        if data['phase1']['buffer_resp'] in buf_resp:
            results['GradingCheck1'] = "Success -- Buffer Overflow C program executed with vulnerability present."
        else:
            results['GradingCheck1'] = "Failure -- Buffer Overflow C program not executed, contains incorrect code, or has the wrong name."

    ## Grade integer overflow C program
    try:
        stdin, stdout, stderr = ssh.exec_command(cmds[1], timeout=5)
        buf_resp = stdout.read().decode().strip()
    except Exception as e:
        results['GradingCheck2'] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
    else:
        tmp_lines = buf_resp.split('\n')
        numStr = tmp_lines[-1].split(':',1)[1].strip()
        numStr = numStr.replace('$','')
        if int(numStr) < 0:
            results['GradingCheck2'] = "Success -- Integer Overflow C program executed with vulnerability present."
        else:
            results['GradingCheck2'] = "Failure -- Integer Overflow C program not executed, contains incorrect code, or has the wrong name."
    ssh.close()
    return results


def phase2(sub=None):
    results = dict()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('kali.hub',username='user',password='tartans',timeout=10)
    except paramiko.Exception as e:
        #print(str(e))
        results['GradingCheck3'] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
        results['GradingCheck4'] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
        ssh.close()
        return results
    
    ## Start grading checks on C Programs
    cmds = ['echo "aaaaaaaaaaaa" | ./Desktop/buffer_patched', 'echo "999999999999999" | ./Desktop/integer_patched']

    ## Grade buffer overflow C program
    try:
        stdin, stdout, stderr = ssh.exec_command(cmds[0], timeout=5)
        buf_resp = stdout.read().decode().strip()
    except Exception as e:
        results['GradingCheck3'] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
    else:
        if data['phase2']['buffer_resp'] in buf_resp:
            results['GradingCheck3'] = "Success -- Buffer Overflow C program executed with vulnerability patched."
        else:
            results['GradingCheck3'] = "Failure -- Buffer Overflow C program not executed, contains incorrect code, or has the wrong name."

    ## Grade integer overflow C program
    try:
        stdin, stdout, stderr = ssh.exec_command(cmds[1], timeout=5)
        buf_resp = stdout.read().decode().strip()
    except Exception as e:
        results['GradingCheck4'] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
    else:
        if data['phase2']['integer_resp'] in buf_resp:
            results['GradingCheck4'] = "Success -- Integer Overflow C program executed with vulnerability patched."
        else:
            results['GradingCheck4'] = "Failure -- Integer Overflow C program not executed, contains incorrect code, or has the wrong name."
    ssh.close()
    return results
    

def phase3(sub=None):
    results = dict()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('target.skills.hub',username='user',password='tartans',timeout=10)
    except paramiko.Exception as e:
        #print(str(e))
        results['GradingCheck5'] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
        ssh.close()
        return results
    
    ## Start grading checks on C Programs
    cmds = ['python3 grade.py']

    ## Grade buffer overflow C program
    try:
        stdin, stdout, stderr = ssh.exec_command(cmds[0], timeout=5)
        gradeResp = stdout.read().decode().strip()
        gradeDict = json.loads(gradeResp)
    except Exception as e:
        results['GradingCheck5'] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
    else:
        if gradeDict['lab']['search']['solved'] == True:
            results['GradingCheck5'] = "Success -- Retrieved sensitive data using SQL Injection."
        else:
            results['GradingCheck5'] = "Failure -- SQL Injection has not been executed or did not retrieve sensitive data."
    ssh.close()
    return results


def phase4(sub=None):
    results = dict()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('target.skills.hub',username='user',password='tartans',timeout=10)
    except paramiko.Exception as e:
        #print(str(e))
        results['GradingCheck6'] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
        ssh.close()
        return results
    
    ## Start grading checks on C Programs
    cmds = ['python3 grade.py']

    ## Grade buffer overflow C program
    try:
        stdin, stdout, stderr = ssh.exec_command(cmds[0], timeout=5)
        gradeResp = stdout.read().decode().strip()
        gradeDict = json.loads(gradeResp)
    except Exception as e:
        results['GradingCheck6'] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
    else:
        if gradeDict['lab']['info']['solved'] == True:
            os.system("cp -r /home/user/skillsHub/c_code/ml/* /home/user/skillsHub/hosted_files/")
            results['GradingCheck6'] = "Success -- Retrieved sensitive data using OS Command Injection."
        else:
            results['GradingCheck6'] = "Failure -- OS Command Injection has not been executed or did not retrieve sensitive data."
    ssh.close()
    return results


def mini_lab(sub=None):
    results = dict()
    cmds = {
        "1": { # Should truncate input 
            "cmd":'echo -e "admin\naaaaaaaaaaaa\n" | ./Desktop/mini_challenge_buffer',
            "resp":'Login failed!',
            "token": "GradingCheck7"
        },
        "2": { # Should be able to accept number larger than INT, less than LONG, and returns msg when number larger than LONG is entered.
            "cmd":'echo "-1\n0\n" | ./Desktop/mini_challenge_integer',
            "resp":'Invalid',
            "token": "GradingCheck8"
        },
        "34": {
            "cmd":'python3 grade.py',
            "resp":'success',
            "token":["GradingCheck9","GradingCheck10"]
        }
    }
    for k,v in cmds.items():
        if k == '1':
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect('kali.hub',username='user',password='tartans',timeout=10)
            except paramiko.Exception as e:
                #print(str(e))
                results[v['token']] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
                ssh.close()
                continue
                #return results

            try:
                stdin, stdout, stderr = ssh.exec_command(v['cmd'], timeout=5)
                buf_resp = stdout.read().decode().strip()
            except Exception as e:
                results[v['token']] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
                ssh.close()
                continue
            else:
                if v['resp'] in buf_resp:
                    results[v['token']] = "Success -- Correct code implemented into Buffer Overflow C program and executed correctly."
                else:
                    results[v['token']] = "Failure -- Buffer Overflow C program not executed, contains incorrect code, or has the wrong name."
            ssh.close()
        elif k == '2':
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect('kali.hub',username='user',password='tartans',timeout=10)
            except paramiko.Exception as e:
                #print(str(e))
                results[v['token']] = "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
                ssh.close()
                continue
                #return results

            try:
                stdin, stdout, stderr = ssh.exec_command(v['cmd'], timeout=5)
                buf_resp = stdout.read().decode().strip()
            except Exception as e:
                results[v['token']] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
                ssh.close()
                continue
            else:
                if v['resp'] in buf_resp:
                    results[v['token']] = "Success -- Correct code implemented into Integer Overflow C program and executed correctly."
                else:
                    results[v['token']] = "Failure -- Integer Overflow C program not executed, contains incorrect code, or has the wrong name."
            ssh.close()
        else:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect('target.skills.hub',username='user',password='tartans',timeout=10)
            except paramiko.Exception as e:
                #print(str(e))
                results[v['token'][0]]= "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
                results[v['token'][1]]= "Failure -- Exception occurred during SSH Connection. Please ensure connectivity and try again."
                ssh.close()
                return results
            
            ## Start grading checks on C Programs
            cmds = ['python3 grade.py']

            ## Grade buffer overflow C program
            try:
                stdin, stdout, stderr = ssh.exec_command(cmds[0], timeout=5)
                gradeResp = stdout.read().decode().strip()
                gradeDict = json.loads(gradeResp)
            except Exception as e:
                results[v['token'][0]] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
                results[v['token'][1]] = "Failure -- Exception occurred during SSH Connection. Please check network and try again"
                ssh.close()
                return results
            else:
                if gradeDict['ml']['login']['solved'] == True:
                    results[v['token'][0]] = "Success -- SQL Injection has been used to login to the website."
                else:
                    results[v['token'][0]] = "Failure -- SQL Injection has not been executed or did not work correctly."

                if gradeDict['ml']['files']['solved'] == True:
                    results[v['token'][1]] = "Success -- Sensitive data has been retrieved using OS Command Injection"
                else:
                    results[v['token'][1]] = "Failure -- SQL Injection has not been executed or did not retrieve the indicated data."
            ssh.close()
    return results



if __name__ == '__main__':
    ## Correct response
    phases = ['phase1','phase2','phase3', 'phase4', 'mini_lab']
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
