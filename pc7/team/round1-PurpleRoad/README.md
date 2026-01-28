# The Purple Road

This challenge is a mixture of Red and Blue team tasks ranging from log analysis to service exploitation.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analyst](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1047](https://niccs.cisa.gov/tools/nice-framework): Perform network reconnaissance and service discovery.
- [T1052](https://niccs.cisa.gov/tools/nice-framework): Identify and exploit misconfigurations.
- [T1084](https://niccs.cisa.gov/tools/nice-framework): Analyze system and network logs.
- [T1101](https://niccs.cisa.gov/tools/nice-framework)


## Background

You have been hired to perform Red Team and Blue Team tasks in the provided environment. Your client has a running `fileserver` on the network and wants you to test its security defenses and increase other defenses. They also would like you to investigate the cause of a recent attack on their system.

## Getting Started

**To access the grader**, navigate to `http://grader` in a web browser and you will be provided access to the form.

## Team Dynamics

**Red Team**: The Red Team will be responsible for the objectives for tokens one and two. NOTE: These tasks do not require the `grader`.  
**Blue Team**: The Blue Team must conduct deep log analysis on the `logserver` to obtain the remaining six tokens. NOTE: These tasks do require use of the `grader`.

## Objectives

### Red Team
***Tasks 1 - 2***

The following table contains a listing of the tokens that are obtainable by the Red Team and which tasks they are tied to. For example, Task 1 corresponds with `Question 1` in the platform:

|owner|task id|objective|grader required|
|------|------|------|-------|
|red team|1|Gain access to the `fileserver`|no|
|red team|2|Gain `root` access to a hidden server|no|

### Blue Team
***Task 3: Blue Team Form Submissions (Grader)***  
Conversely, the following table contains a listing of the tokens that are obtainable by the Blue Team. Within the `grader`, answering a question correctly will yield its corresponding token.

|owner|task id|objective|grader required|
|------|------|------|-------|
|blue team|3.1|Which user successfully logged in from 172.19.0.5 on port 2222?|yes|
|blue team|3.2|Which command did the attacker run with `sudo`? (example: /bin/command /file/arg)|yes|
|blue team|3.3|Where did the attacker connect for C2 from? (example: example.com:1234)|yes|
|blue team|3.4|Which CVE was used to perform privilege escalation? (example: CVE-999-9999)|yes|
|blue team|3.5|Find the token hidden in the logs on the `logserver`|no|


***Task 4: Secure Configurations***  
To obtain the final tokens of this challenge, perform the following tasks on the `fileserver` after the red team has given you access:

|owner|task id|objective|grader required|
|------|------|------|-------|
|blue team|4.1|Disable the misconfiguration that allowed the Red Team to gain initial access.|yes|
|blue team|4.2|Configure `fail2ban` to protect the `ftp` service|yes|
|blue team|4.3|Ensure no world-writable files in `/home`|yes|

Once complete, use the `grader` to submit your request for validation (located near the bottom of the form). Once submitted, you will be notified on whether or not the objectives were appropriately completed.


## Tokens 
Tokens will be in the format `PCCC{value_XX_XXXX}`.

## System and Tool Credentials

|system/tool|hostname|username|password|
|-----------|--------|--------|--------|
|logserver|`logserver`|user|password|
|fileserver|`fileserver`|N/A|N/A|
|*unknown asset|TBD|TBD|TBD|

* NOTE: The Red Team is tasked with discovering this asset in Question/Task 2.
