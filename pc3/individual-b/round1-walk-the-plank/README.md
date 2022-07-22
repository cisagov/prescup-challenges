# Walk the Plank

Exploit a given program to find the tokens.

  **NICE Work Role:**

  [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)

  [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Vulnerability+Assessment+Analyst&id=All)


  **NICE Tasks:**

  - [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0641&description=All)  - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.  

  - [T0736](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0736&description=All) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## Background

  You've been provided a program called `buffer`. Once hosted on a port with the `host.sh` script, interacting with the program on localhost 11111 will prompt you for a username and password. There is a fault in the code and you can attempt to write one or more exploits to capitalize on the vulnerability.
  
## Getting Started
  
  Make sure that all files from the challenge folder are downloaded and placed in the same folder. 
  
  On Debian Operating Systems, use the following command to turn off ASLR:
  ```
  echo "kernel.randomize_va_space = 0" > /etc/sysctl.d/01-disable-aslr.conf
  ```
 

  The provided `host.sh` script will host the provided binary program on TCP port 11111 using `netcat`. Ensure the `host.sh` script is executable and run the script in the background to start hosting the binary executable:
  ```
  chmod +x host.sh && ./host.sh &
  ```
  
  To begin the challenge, connect to the hosted program with the command:
  ```
  nc localhost 11111
  ``` 


## Token Retrieval

  Tokens will be awarded by properly altering program execution. There are three(3) tokens for this challenge. They will be 16 character hex strings. 

**Part 1**: You will receive a token from the program after entering the correct password (token in `login.txt`).

**Part 2**: Alter program execution to call the secret function and reveal the second token (token in `secret.txt`).
  
**Part 3**: Gain shell access to the service and find this token in the files (token in `shell_token.txt`). 
  

