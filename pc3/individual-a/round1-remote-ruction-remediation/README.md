# Remote Ruction Remediation

Remotely triage and clean an infected system. 


**NICE Work Role:** 


- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework).
- [T0278](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment. 

## Background

Based on intel it is known that APT15 is operating from the 200.205.105.10 IP address. A system compromised by this threat actor usually communicates with the malicious IP on port 9342. Usually, the compromised system also contains a rogue user account on it. A threat hunter searched your enterprise and found 10.5.5.200 communicating with the malicious IP address.


## Getting Started

Your goal is to **remotely** clean the infected system (10.5.5.200) and prevent it from communicating with the malicious IP. To do so, you will need to - 
1. Gain remote access to the infected system
1. Stop the malicious process 
2. Delete the malicious executable
3. Delete the malicious user account
4. Create a firewall rule on the infected system to block traffic to malicious IP

The grading results can be accessed from the `analyst` VM by browsing to `http://challenge.us`. Each successful grading check will yield an 8-character hexadecimal string for submission.

| Grading Check # | Grading Check Description                                    | Weight |
| :-------------: | ------------------------------------------------------------ | :-------: |
|        1        | Malicious process is not running |    20%    |
|        2        | Malicious executable is not present |    20%    |
|        3        | Malicious user account is not present |    20%    |
|        4        | Firewall rule blocking traffic to malicious IP is in place |    40%    |

## Things to keep in mind
1. Both `analyst` and `infected` systems are not on a domain
2. The `infected` system is already setup for powershell remoting
3. The admin credentials for the `infected` system are `Administrator/tartans`

## System and Tool Credentials

| system/tool | username | password |
|-------------|----------|----------|
| analyst  |   user    |  tartans  |
| infected |  Administrator | tartans |



## Note
Attacking or unauthorized access to challenge.us (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
