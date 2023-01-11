#!/usr/bin/python3

import socket
from _thread import *

def conn(keyList):
    host,port = 'services',22222
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host,port))
        rec = str(sock.recv(1024), 'utf-8')
        print(rec)
        for key in keyList:
            print(f"\n\n---------------Key being tested: {key}-------------------\n")
            key = key.strip('\n')
            for let in key:
                sock.sendall(bytes(let+'\n',"utf-8"))
                print("number sent: " + str(let))
                rec = str(sock.recv(1024), 'utf-8')
                if 'next' in rec:
                    print(f"response: {rec}\n")
                    continue
                elif 'Incorrect' in rec:
                    print(f"response: {rec}\n")
                    break
                elif 'More' in rec:
                    print(f"response: {rec}\n")
                    break
                else:                               # catches if correct
                    print(f'\nresponse: \n\n{rec}')
                    sock.close()
                    return
        sock.close()
                                

def getKeys():
    keyList = list()
    with open("decodedKeys.txt", 'r') as f:
        keys = f.readlines()
    for key in keys:
        keyList.append(key.strip('\n'))
    return keyList
        
if __name__=='__main__':
    keyList = getKeys()
    conn(keyList)
