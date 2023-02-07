#!/usr/bin/python3

import subprocess, secrets, sys, json, hashlib
import pandas as pd

def checkSyntax(jobStr):
    jobWords = list()
    # remove extra characters
    if ',' in jobStr:
        jobStr = jobStr.replace(',','')
    if '(' in jobStr:
        jobStr = jobStr.replace('(','')
        jobStr = jobStr.replace(')','')
    if '-' in jobStr:
        jobStr = jobStr.replace('-',' ')
    # Split into list
    jobWords = jobStr.split(' ')
    if '' in jobWords:
        jobWords.remove('')
    return jobWords


def createWebCreds(rec):    # solution: must create all possible user:pwd combinations to brute force
    webCreds = dict()
    for k,v in rec.items():
        ## create username
        partEmail = v['mail'][:v['mail'].index('@')]
        jobWords = checkSyntax(v['job'])
        initials = ''
        for x in jobWords:
            initials += x[0]
        username = partEmail+f'.{initials}_{len(jobWords)}'
        ## create password
        bdList = v['birthdate'].split('/')
        tmpBdVal = 0
        for val in bdList:
            tmpBdVal += int(val)
        ssnList = v['ssn'].split('-')
        bdValue = tmpBdVal % int(ssnList[0])
        ssnStr = str(ssnList[1]) + str(ssnList[2])
        password = str(bdValue)+f".{v['sex']}{ssnStr}-{v['blood_group']}"
        webCreds[username] = password

    with open('webCreds','w+') as f:
        f.write(json.dumps(webCreds, indent=2))

if __name__ == '__main__':
    rec = pd.read_csv('websiteRecords.csv').to_dict('index')
    createWebCreds(rec)
