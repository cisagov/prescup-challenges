# Covert Conundrum

Complete two challenges that involve identifying Indicators of Compromise and killing malicious processes in a simulated office environment.

**NICE Work Roles**

- [Defensive Cybersecurity](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Incident Response](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify anomalous network activity
- [T1085](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify potential threats to network resources
- [T1348](https://niccs.cisa.gov/workforce-development/nice-framework/): Distinguish between benign and potentially malicious cybersecurity attacks and intrusions
- [T1616](https://niccs.cisa.gov/workforce-development/nice-framework/): Resolve computer security incidents


## Background 

1. A machine located within the corporate network is showing signs of compromise spamming its local subnet with network traffic. 

1. The central server is not receiving correctly formatted data. We suspect it is because of an attacker's activity.

1. You are tasked with locating the source of the network traffic and stopping the spam. However, this may not be the only machine compromised on the network. You need to resolve all active malicious connections on the network and correct any data integrity issues.

## Getting Started 

This environment contains machines that are compromised and machines that are not compromised.

Using the provided `kali-challenger` machine, you may use `ssh` to login to any machine on the network by invoking `ssh`.


To grade your challenge and acquire the tokens, you must use a browser to go to `https://challenge.us`. Once you are successful and acquire a token, submit the token on the challenge page.

**NOTE:** Once the challenge environment is complete, the grading site may take up to a full minute to grade.

The tokens are awarded after the processes have been confirmed permanently killed.

**If you power off any of the machines, you will have to restart your environment. Rebooting is allowed.**

This challenge has 2 parts:

## Part 1: Stop the spamming

- As stated in the Background section, a machine spamming its subnet. To earn the first token, identify and kill the running process to stop the traffic spamming.

## Part 2: Malicious connections

- For tokens 2 and 3, find any malicious connections and kill them while fixing any data integrity issues you find.

## Part 3: Any other malicious connections

- For the remaining token, identify any other malicious traffic, including connections from the outside. Stop the processes and correct any data integrity issues you find.

## System and Tool Credentials

|system/tool|operating system|username|password|
|-----------|--------|--------|--------|
|kali-challenger|Debian/Kali Linux|user|tartans|
|All Internal Machines|various|user|tartans|
|10.5.5.1|VyOS|user|tartans|
|https//[]()10.0.0.1|pfsense|user|tartans|
|https://[]()10.4.4.4|securityOnion|admin[]()@so.org|tartans@1|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.