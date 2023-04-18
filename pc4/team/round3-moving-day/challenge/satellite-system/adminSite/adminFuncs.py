#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys, os, datetime, subprocess, urllib.parse
from http import server
from flask import g
sys.path.insert(0, './adminSite/')
import globals
  
def restartSite():
    globals.logger.info("Restarting website")
    subprocess.run("sudo systemctl restart adminSite",shell=True)

def syntaxCheck(cmdStr, cmdOrSeq):
    if cmdOrSeq == 'cmd':
        correctCmds = dict()
        cmdList = cmdStr.split('\r\n')
        if '' in cmdList:
            cmdList.remove('')
        if len(cmdList) > globals.max_cmds:         
            cmdList = cmdList[:globals.max_cmds]
        for x in range(len(cmdList)):
            cmdWords = cmdList[x].split(' ')
            if '' in cmdWords:
                cmdWords.remove('')
            # check for correct number of arguments/parameters
            if len(cmdWords) != 4:
                error = [f"Error with cmd: {cmdList[x]}.","Incorrect number of parameters."]
                return error
            # handle if they enter 'degrees' vs 'degree'
            if cmdWords[3][-1] == 's':
                cmdWords[3] = cmdWords[3][:-1]
            if cmdWords[0].lower() != globals.cmdSyntax[0]:        # check for 'move'
                error = [f"Error with cmd: {cmdList[x]}.","'move' missing/incorrect."]
                return error
            elif cmdWords[1].lower() not in globals.cmdSyntax[1]:  # check azi,ele
                error = [f"Error with cmd: {cmdList[x]}.","Direction missing/incorrect."]
                return error
            elif cmdWords[2] not in globals.cmdSyntax[2]:          # check -1,+1
                error = [f"Error with cmd: {cmdList[x]}.","Increment missing/incorrect."]
                return error
            elif cmdWords[3].lower() not in globals.cmdSyntax[3]:  # check deg, min, sec
                error = [f"Error with cmd: {cmdList[x]}.","Value to increment missing/incorrect."]
                return error
            else:
                correctCmds[x]=cmdWords[1:]
                continue
        return correctCmds
    elif cmdOrSeq == 'seq':
        pass

def sendCommands(cmds):
    if len(cmds) == 1:
        for k,v in cmds.items():
            cmdStr = ':'.join(v)
            cmdEncdoed = urllib.parse.quote_plus(cmdStr)
        cmd = f"curl -m 1 127.0.0.1:{globals.satPort}/run?cmd={cmdEncdoed}"
        out = subprocess.run(cmd,shell=True,capture_output=True).stdout.decode('utf-8')
        return
    else:
        cmdList = list()
        for k,v in cmds.items():
            cmdStr = ':'.join(v)
            cmdEncdoed = urllib.parse.quote_plus(cmdStr)
            cmdList.append(cmdEncdoed)
        allCmds = '.'.join(cmdList)
        cmdEncoded = urllib.parse.quote_plus(allCmds)
        cmd = f"curl -m 1 127.0.0.1:{globals.satPort}/run?cmd={cmdEncoded}"
        out = subprocess.run(cmd,shell=True,capture_output=True).stdout.decode('utf-8')
        return
