#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, sys, subprocess, json, pexpect, time

def noArgs(sshpwd):
    tmpCmds =  pexpect.run(f"sudo ssh -o StrictHostKeyChecking=no hector@ext 'cat cmdList'",events={'(?i)password':sshpwd+'\n'}).decode('utf-8').split('\n')
    cmds = [x.strip('\r') for x in tmpCmds]
    cmds.pop(0)
    cmds.remove('')
    outputDict = dict()
    print(f"Running commands...")
    for c in range(len(cmds)):
        tmpOut = subprocess.run(cmds[c], shell=True,capture_output=True)
        outputDict[c] = {'cmd':cmds[c],'stdout':tmpOut.stdout.decode('utf-8'),'stderr':tmpOut.stderr.decode('utf-8')}
    tst = pexpect.run(f'sudo ssh -o StrictHostKeyChecking=no hector@ext "echo {outputDict} | tee cmdOutput"',events={'(?i)password':sshpwd+'\n'}).decode('utf-8')
    print("Results stored.")

def withArgs(args, sshpwd):
    outputDict = dict()
    pexpect.run(f"sudo ssh -o StrictHostKeyChecking=no hector@ext 'echo gtg'",events={'(?i)password':sshpwd+'\n'})
    for a in args:
        fullPath = os.path.abspath(a)
        if os.path.isfile(fullPath) == True:
            with open(os.path.abspath(a), 'r') as f:
                tmp = f.readlines()
            if len(tmp) == 0:
                print("no cmds found in file")
                continue
            cmds = [x.strip('\r') for x in tmp]
            cmds = [x.strip('\n') for x in tmp]
            if '' in cmds:
                cmds.remove('')
            for c in range(len(cmds)):
                tmpOut = pexpect.run(f"sudo ssh -o StrictHostKeyChecking=no hector@ext '{cmds[c]}'",events={'(?i)password':sshpwd+'\n'}).decode('utf-8')
                outputDict[c] = {'cmd':cmds[c],'output':tmpOut[32:]}
        elif type(a) == str:
            tmpOut = pexpect.run(f"sudo ssh -o StrictHostKeyChecking=no hector@ext '{a}'",events={'(?i)password':sshpwd+'\n'}).decode('utf-8')
            index = 0 if len(outputDict) == 0 else len(outputDict)+1
            outputDict[index] = {'cmd':a,'output':tmpOut[24:]}
        else:
            outputDict[a] = {'cmd':a, 'error':'Incorrect format, passed args need to be either file or string.'}

    for k,v in outputDict.items():
        print("cmd:\t",v['cmd'])
        if 'error' in v:
            print('error:\t', v['error'])
        else:
            print("output:\t", v['output'])

if __name__=='__main__':
    sshpwd = '#sshpwd'
    if len(sys.argv) == 1:
        noArgs(sshpwd)
    else:
        withArgs(sys.argv[1:], sshpwd)
