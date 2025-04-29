# Decoy Massacre

A HoneyNet is actively being infiltrated. Your job is to send data to the attacker and remediate the environment.

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics)
- [Incident Response](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/incident-response)

**NICE Tasks**
- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensicsy): Identify anomalous network activity.
- [T1102](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics): Identify Intrusions
- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensicss): Identify vulnerabilities


## Background

A novice attacker is connected to the organization's HoneyNet. Your job is to distract the attacker by sending data derived from the HoneyNet to the attacker's machine while also remediating any vulnerabilities or compromises identified in the HoneyNet.

## Getting Started

The environment contains many different machines. 

Using the provided `kali-challenger` machine, you may use `ssh` to log in to any machine, but `ssh` may not always be available.

The following networks exist:

- 10.0.0.0/8: The HoneyNet
- 123.45.67.0/24: The WAN

To grade your challenge and acquire the tokens, you must use a browser to go to `https://challenge.us`. Once you are successful and acquire a token, submit the token on the challenge page.

The tokens are awarded when the environment satisfies the conditions. 

## Submissions

There are four (4) tokens to retrieve in this challenge. Each token is an eight (8) character hexadecimal string. Notes on each token are provided below.

**Question 1:** There is a secret passphrase hosted on the HoneyNet. To distract the attacker, identify the passphrase and send it to the attacker machine.

**Question 2:** There is a secret passphrase being sent between machines on the HoneyNet. To distract the attacker, identify the passphrase being exchanged and send it to the attacker machine.

**Question 3:** Identify and turn off any compromised machines. **WARNING**: If you turn off a machine that is not compromised, you may break the grading and have to destory and reload your instance.

**Question 4:** Identify any vulnerable services running and remediate them. **NOTE**: To get this token, the machine containing the vulnerable service must be alive and remediated.

From the provided Kali machine, browse to `https://challenge.us` and run the grading script. You can run the grading script as many times as needed while you make the required application changes. You will be given a token for each of the four tasks described above.  

## Challenge Tasks

1. Send the hosted passphrase on the HoneyNet to the attacker machine.
2. Send the exchanged passphrase on the HoneyNet to the attacker machine.
3. Turn off all compromised machines.
4. Remediate vulnerable services on machines. 


## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-challenger|user|tartans|
|all machines|user|tartans|
|pfsense https//:[]()123.45.67.89|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.