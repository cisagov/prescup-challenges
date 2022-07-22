# SSH Rotate Solution

## Part 1 - Analysis

Wireshark will reveal regular ssh connection attempts. If SSH server is enabled on the target Kali
machine, the system logs will show numerous and persistent SSH connection attempts. The usernames
will loop in the same order approximately every hour. Nothing else interesting can be discovered at
this point.

## Part 2 - Solve

### Naive Approach (Theory Only)

The attack consists of a list of usernames and a list of passwords. Each list is a different length. A
single counter is used to select a username and a password from each list. A modulo operation is used
to prevent an index out of bounds exception. This attacker approach results in the victim seeing every
username and every password in a very short amount of time, while ensuring that no specific username/password
combination will be reused within the time frame of the challenge. This is in contrast to a traditional
nested loop approach, which would try every password with the first username, then every password with the
second username, and so on. The victim would never see the last username (and many before it) because
the challenge would end too soon. It would also make it very easy to build a password list, then wait for
the next username to be exposed and create an account with that name and a password from late in the list.

The naive solution is to build an SSH server that listens for and logs all the usernames and all the
passwords, then determine the pattern and predict a future username/password combination. Then create
a user account with those credentials, wait for the attacker to connect, and recover the solution. The
effort required to build the SSH listening server gets participants 99% of the way to the easy solution.

### Best Approach (Code Supplied)

Once an SSH server is built, it can be instructed to simply authorize ANY username/password request. Once
authorized, the remote client will send a command. The SSH server can simply print that command to stdout
and the participant can note the submission token. Kali includes a Python library called Paramiko that
provides everything needed to build an SSH server (and client) in Python. Script is provided in the [solution](solution) folder with filename [script.py](solution/script.py).


### Paramiko RSA Key Note

In order to generate a private key that Paramiko can use, first use ssh-keygen to create id_rsa in your ~/.ssh/
directory, then do ssh-keygen -p -m PEM -f id_rsa to convert it. You might want to copy it to a new file first
so that your private key doesn't get overwritten. This file will then be the sole argument to the script and can be run this way:

```
sudo python3 script.py id_rsa
```

### Part 3 - Solution

Read the submission token from submission.txt in the compromised user's home directory (naive approach) or
from stdout (best approach). It is the following sixteen character hexadecimal string: `0d2839ede999a5bb`.