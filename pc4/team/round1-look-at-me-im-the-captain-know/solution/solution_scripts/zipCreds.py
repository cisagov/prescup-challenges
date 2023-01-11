#!/usr/bin/python3

import subprocess
from bs4 import BeautifulSoup

def getData():
    # read in HTML file
    with open('manifest.html') as f:
        html = f.read()
    soup = BeautifulSoup(html, features="html.parser")
    # remove extra items in HTML code 
    for script in soup(["script", "style"]):
        script.extract()
    # parse HTML data into string
    text = soup.get_text()
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split(" "))
    text = '\n'.join(chunk for chunk in chunks if chunk)
    # Find first mention of item in string, make it starting point of new string
    firstItem = text.find('1.')
    text = text[firstItem:]
    # turn string into dictionary for easier iteration
    txtList = text.split('\n')
    numList = list()
    itemDict = dict()
    # create list of all know item numbers to make matching easier in loop
    for x in range(1,67):
        numList.append(str(x)+'.')
    index = 0       # index of full HTML string
    tmpID = 0       # ID of item in cargo list
    totalWeight=page1Weight=page2Weight=page3Weight = 0
    # create loop to grab item & its weight based on number
    while True:
        if txtList[index] in numList:
            tmpID = txtList[index].strip('.')
            tmpValue = ''
            index += 1
            while txtList[index] not in numList:
                if 'lbs' in txtList[index]:
                    tmpWeight = txtList[index].strip('lbs')
                    totalWeight += int(tmpWeight)
                    if tmpID <= '22':
                        page1Weight += int(tmpWeight)
                    elif (tmpID > '22') and (tmpID <= '44'):
                        page2Weight += int(tmpWeight)
                    else:
                        page3Weight += int(tmpWeight)
                    tmpValue += txtList[index]
                else:
                    tmpValue += txtList[index]+' '
                index += 1
                if index >= len(txtList):
                    break
            if 'SIGNATURE' in tmpValue:
                tmpIndex = tmpValue.find('SIGNATURE')
                tmpValue = tmpValue[:tmpIndex]
            itemDict[tmpID] = tmpValue
        if txtList[index - 1] == txtList[-1]:
            break

    print('ID','    Item','     Weight')
    print('----------------------------------------------------------')
    allPwds=list()
    for k,v in itemDict.items():
        print(k,v)
        stringList = v.split()
        stringList.pop(-1)
        curPwd = ''
        for word in stringList:
            curPwd += word[0]
        allPwds.append(curPwd+str(page1Weight))
        allPwds.append(curPwd+str(page2Weight))
        allPwds.append(curPwd+str(page3Weight))
        allPwds.append(curPwd+str(totalWeight))
    
    with open('possZipPasswords.txt','w+') as f:
        for pwd in allPwds:
            f.write(pwd+'\n')

    print('----------------------------------------------------------')
    print("Total weight of all items on first page of cargo manifest: ",str(page1Weight)+'lbs')
    print("Total weight of all items on second page of cargo manifest: ",str(page2Weight)+'lbs')
    print("Total weight of all items on third page of cargo manifest: ",str(page3Weight)+'lbs')
    print("Total weight of items on cargo manifest: ",str(totalWeight)+'lbs')
    return allPwds

def bruteForce(allPwds):
    print('----------------------------------------------------------')
    print("Starting attempts to unzip password protected zip:")
    for p in allPwds:
        res = subprocess.run(f"sudo unzip -c -P {p} file.zip",shell=True, capture_output=True).stderr.decode('utf-8')
        if 'incorrect password' not in res:
            print(f'Zip unlocked. Correct password is: {p}')
            with open('zipPassword.txt', 'w+') as f:
                f.write(p)
            break

if __name__=='__main__':
    allPwds = getData()
    bruteForce(allPwds)
