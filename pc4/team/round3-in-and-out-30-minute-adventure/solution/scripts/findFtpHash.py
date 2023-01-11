#!/usr/bin/python3

import itertools, hashlib

def findPwd():
    splitHash = ['hash','list','goes','here','!']
    possCombinations = list(itertools.permutations(splitHash, 5))

    ftpPwdList = list()
    with open('ftpRotatingPwds', 'r') as f:
        for line in f.readlines():
            ftpPwdList.append(line.strip('\n'))
            
    for p in possCombinations:
        for f in ftpPwdList:
            ## Create new string of currently selected order of 5 hash strings
            combinationStr = ''.join(p)
            ## Get SHA1 hash of currently selected FTP Password
            encodedStr = f.encode()
            ftpSha1Hash = hashlib.sha1(encodedStr)
            ftpHashStr = ftpSha1Hash.hexdigest()
            if combinationStr == ftpHashStr:
                print(f"Hash match found!\nPassword is: {f}")    

if __name__=='__main__':
    findPwd()
