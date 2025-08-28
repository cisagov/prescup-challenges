# Keylogged

Your team has been tasked with seeing what information was exfiltrated from machines infected with keylogging malware at an organization.

**NICE Work Roles**
- [Digital Forensics](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
- [T0179](https://niccs.cisa.gov/workforce-development/nice-framework): Perform static media analysis
- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework): Identify anomalous network activity
- [T1191](https://niccs.cisa.gov/workforce-development/nice-framework): Determine relevance of recovered data

## Background

Use the provided Kali and Security Onion machines to examine files and information going across the network. 

## Getting Started

Our team has recovered two files (`1keyfileA.txt` and `1keyfileB.txt`) from a victim machine on the network that contain they keylogged data. The files can be downloaded at `challenge.us`. 

Log in to the Kali VM and begin investigating.

One victim machine has been left running on the network. It is still exfiltrating data, but it appears to be encrypted with an XOR key. Analyze the web traffic to find what information is still being exfiltrated from a victim machine, and decrypt the data using a 1 byte XOR key (not given). One of the users, Jubilee, believes that she may have logged into an account prior to sending a message to Sarah.  

You can use **Security Onion** to create PCAP files and view the traffic between the client/server. You can do this by logging in to the `securityonion` device directly and creating a packet capture by listening on the `tap0` interface. 

The threat actor seems to have installed the keylogger during an IT support call but forgot they left the keylogger running when they tried to login to their own C2 server. Lucky for us, a core dump was taken of the malicious process. The file (`core.11066`) can be downloaded at `challenge.us`. Use `gdb` to analyze the core dump.

## Submission

There are 5 tokens to retrieve in this challenge. Each token is a 12-character hexadecimal value. The tokens can be retrieved in any order. Tokens 1-3 require a grading check from `challenge.us` while tokens 4 and 5 should be entered as answers directly into the challenge question boxes below. 

- Token 1: What is the token you receive from the grading check for finding the plaintext password that the keylogger captured?
- Token 2: One victim machine is actively transmitting files across the network. What is the token you receive from the grading check for finding the plaintext of the password captured in the keylog files that are being sent across the network?
- Token 3: What is the token you receive from the grading check for finding the **username** used to access the C2 server found in the core dump file?
- Token 4: What is the token found on a hidden webpage on the C2 server?
- Token 5: What is the token found in one of the C2 server's keylogger logs?

## System and Tool Credentials

| system/tool | username | password |
| --- | --- | --- |
| kali-keylogged | user | tartans |
| securityonion | so | tartans |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.