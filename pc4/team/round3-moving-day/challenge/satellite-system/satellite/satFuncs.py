#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from importlib.metadata import files
import sys, os, datetime, subprocess, urllib.parse, time
from http import server
sys.path.insert(0, './')
import globals


def restartSat():
    globals.logger.info("Restarting satellite")
    subprocess.run("sudo systemctl restart satellite",shell=True)

def getCurrentState():
    cnt = 0
    for k,v in globals.fileInfo.items():
        if v['passed'] == 'True':
            cnt += 1
    globals.status['current_state'] = str(cnt)
    if cnt > 2:
        globals.fatal = 'True'

def checkCoordinates():
    points = ['aDegree','aMinute','eDegree','eMinute'] 
    for f in globals.files:
        chk = True
        for p in points:
            if (globals.status[p] != f[p]):
                chk = False
                break
        if chk == True:
            curFile = f['name']
            # transfer file to Wesbite
            globals.fileInfo[curFile]['passed'] = 'True'
            subprocess.run(f"cp {globals.fileInfo[curFile]['loc']} {globals.storage}",shell=True)
            globals.status[curFile] = 'True'
    getCurrentState()


def moveSat(cmd):
    # decode URL encoding in cmd
    cmdDecoded = urllib.parse.unquote(cmd)
    globals.status['cmd_running'] = 'True'
    if globals.status['current_state'] == '0':
        if '.' not in cmdDecoded:   # if its 1 command
            time.sleep(globals.timePerCmd)
            cmdWords = cmdDecoded.split(':')
            # concatenate specific characters in cmd to create dictionary entries (ex: aDegree, eMinute, etc.)
            tmp = cmdWords[0][0]+cmdWords[2]
            for k,v in globals.status.items():
                if tmp.lower() == k.lower():
                    globals.status[k] = eval(f'{v}{cmdWords[1]}')
        else:
            # multiple cmds sent are seperated with '.'
            cmdList = cmdDecoded.split('.')
            for cmd in cmdList:
                time.sleep(globals.timePerCmd)
                cmdWords = cmd.split(':')
                # concatenate specific characters in cmd to create dictionary entries (ex: aDegree, eMinute, etc.)
                tmp = cmdWords[0][0]+cmdWords[2]
                for k,v in globals.status.items():
                    if tmp.lower() == k.lower():
                        globals.status[k] = eval(f'{v}{cmdWords[1]}')
        globals.status['cmd_running'] = 'False'
        return
    # does opposite of commands sent, ex: +1 -> -1
    elif globals.status['current_state'] == '1':
        if '.' not in cmdDecoded:
            time.sleep(globals.timePerCmd)
            cmdWords = cmdDecoded.split(':')
            # concatenate specific characters in cmd to create dictionary entries (ex: aDegree, eMinute, etc.)
            tmp = cmdWords[0][0]+cmdWords[2]
            for k,v in globals.status.items():
                if tmp.lower() == k.lower():
                    # switch '-' and '+'
                    if '+' in cmdWords[1]:
                        cmdWords[1] = cmdWords[1].replace('+','-')
                    else:
                        cmdWords[1] = cmdWords[1].replace('-','+')
                    globals.status[k] = eval(f'{v}{cmdWords[1]}')
        else:
            # multiple cmds sent are seperated with '.'
            cmdList = cmdDecoded.split('.')
            for cmd in cmdList:
                time.sleep(globals.timePerCmd)
                cmdWords = cmd.split(':')
                # concatenate specific characters in cmd to create dictionary entries (ex: aDegree, eMinute, etc.)
                tmp = cmdWords[0][0]+cmdWords[2]
                for k,v in globals.status.items():
                    if tmp.lower() == k.lower():
                        # switch '-' and '+'
                        if '+' in cmdWords[1]:
                            cmdWords[1] = cmdWords[1].replace('+','-')
                        else:
                            cmdWords[1] = cmdWords[1].replace('-','+')
                        globals.status[k] = eval(f'{v}{cmdWords[1]}')
        globals.status['cmd_running'] = 'False'
        return
    # does opposite every other cmd
    elif globals.status['current_state'] == '2':
        if '.' not in cmdDecoded:
            time.sleep(globals.timePerCmd)
            cmdWords = cmdDecoded.split(':')
            # concatenate specific characters in cmd to create dictionary entries (ex: aDegree, eMinute, etc.)
            tmp = cmdWords[0][0]+cmdWords[2]
            for k,v in globals.status.items():
                if tmp.lower() == k.lower():
                    # switch '-' and '+'
                    if globals.state3CmdTracker % 2 == 1:
                        if '+' in cmdWords[1]:
                            cmdWords[1] = cmdWords[1].replace('+','-')
                        else:
                            cmdWords[1] = cmdWords[1].replace('-','+')
                        globals.status[k] = eval(f'{v}{cmdWords[1]}')
                        globals.state3CmdTracker += 1
                    else:
                        globals.status[k] = eval(f'{v}{cmdWords[1]}')
                        globals.state3CmdTracker += 1
        else:
            # multiple cmds sent are seperated with '.'
            cmdList = cmdDecoded.split('.')
            for cmd in cmdList:
                time.sleep(globals.timePerCmd)
                cmdWords = cmd.split(':')
                # concatenate specific characters in cmd to create dictionary entries (ex: aDegree, eMinute, etc.)
                tmp = cmdWords[0][0]+cmdWords[2]
                for k,v in globals.status.items():
                    if tmp.lower() == k.lower():
                        if globals.state3CmdTracker % 2 == 1:
                            if '+' in cmdWords[1]:
                                cmdWords[1] = cmdWords[1].replace('+','-')
                            else:
                                cmdWords[1] = cmdWords[1].replace('-','+')
                            globals.status[k] = eval(f'{v}{cmdWords[1]}')
                            globals.state3CmdTracker += 1
                        else:
                            globals.status[k] = eval(f'{v}{cmdWords[1]}')
                            globals.state3CmdTracker += 1
        globals.status['cmd_running'] = 'False'
        return
    else:
        globals.fatal = 'True'

def checkTimeout():
    if globals.shutdownInfo['timeout'] == 'True':
        curTime = datetime.datetime.now()
        if curTime < globals.shutdownInfo['timein']:
            globals.shutdownInfo['timeout'] = 'False'
            return 'fail'
    return 'pass'

def shutdownSequence(seq):
    seqList = seq.split('->')
    if seqList == globals.shutdownInfo['correct_seq']:
        globals.shutdownInfo['offline'] = 'True'
        return 'Shutdown Initiated'
    globals.shutdownInfo['attempts'] = int(globals.shutdownInfo['attempts']) + 1
    if int(globals.shutdownInfo['attempts']) >= 3:
        start = datetime.datetime.now()
        tmp = datetime.datetime.timetuple(start + datetime.timedelta(seconds=globals.timeoutLength))
        globals.shutdownInfo['timeout'] = 'True'
        globals.shutdownInfo['timein'] = datetime.datetime.fromtimestamp(time.mktime(tmp))
        globals.shutdownInfo['attempts'] = 0
        return f'3 Incorrect sequences<br>{globals.timeoutLength} second timeout inititated'
    else:
        return 'Incorrect sequence'
