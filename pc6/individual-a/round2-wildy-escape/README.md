# Wildy Escape

Complete 3 challenges using the provided Kali Linux forensic machine to investigate a compromised environment. Submit for grading when ready by using the browser to visit the grading page at https://challenge.us.

**NICE Work Roles**


- [Defensive Cybersecurity](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Incident Response](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify anomalous network activity.
- [T1489](https://niccs.cisa.gov/workforce-development/nice-framework/): Correlate incident data.
- [T1616](https://niccs.cisa.gov/workforce-development/nice-framework/): Resolve computer security incidents.
- [T1391](https://niccs.cisa.gov/workforce-development/nice-framework/): Mitigate potential cyber defense incidents.

## Background 

You are a Senior HUNT Team member deployed to analyze an unknown APT (advanced persistent threat) found in an enterprise network. The owners of system were unaware of the compromise until a blue team detected the malicious activity when their Intrusion Detection System recognized unauthorized shell access to an isolated network.

You are tasked with:
1) Determine the root cause of the compromise.
2) Find any reconnaissance software agents or malicious activity deployed in the network.
3) Detect the presence the command and control mechanisms used by malware, and permanently stop and remove the threat (disable the malware and prevent it from reloading).
4) Stop the APT from further advancing into other networks.

## Getting Started 

Using the provided Kali machine, you can use ssh to login to a machine by invoking ssh user@ip-address, replacing ip-address with the intended machine's IP address.  In all cases the password is `tartans`.

To grade your challenge and acquire the tokens, you must use a browser to go to https://challenge.us. Initiating a grading attempt in the browser will take over a minute each time, and you can click on the refresh button to check if grading has completed.

To get a token, the environment must satisfy the conditions.

## Challenge

### Part 1: The Scanning Device
- Identify any machines that are currently scanning the network.
- Permanently disable any detected asset's ability to scan the network.

### Part 2: Find the source of the compromise
- Identify the source machine of the compromise.
- Permanently disable the source machine's ability to remotely turn on more scanning processes on other machines.

### Part 3: Find more compromises
- Identify and turn off any more compromised machines, services, or processes.


## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|
|ip-address|user|tartans|
|<all other hosts>|user|tartans|

|Network|Subnet Mask|
|-------|-----------|
|10.1.1.0|255.255.255.0|
|10.3.3.0|255.255.255.0|
|10.5.5.0|255.255.255.0|


## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.