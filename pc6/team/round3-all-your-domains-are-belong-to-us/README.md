# All Your Domains Are Belong to Us

Find vulnerabilities in binaries and perform a privilege escalation attack. 

**NICE Work Roles**

- [Cyberspace Operations](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/cyberspace-operations)

**NICE Tasks**

- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/cyberspace-operations): Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0260](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/cyberspace-operations): Analyze identified malicious activity to determine weaknesses exploited, exploitation methods, effects on system and information.

## Background

In this challenge, you will encounter two main components:

1. A program that uses a domain generation algorithm to create a list of domain names for connecting to a c2 server. You will need to analyze the program and its associated network traffic. 
2. A machine with a privilege escalation vulnerability that will allow you to gain root access. You will need to analyze the system, identify the vulnerability, and then exploit it to gain root access.  

## Getting Started

Using the provided Kali machine, you will have access to the necessary tools for packet analysis and binary reverse engineering. 

## Part 1

Download the packet capture (`dga.pcap`) from `challenge.us/files`.

Note: you may need to wait a few minutes after launching the challenge for the `challenge.us` server to become available. 

Your goal is to locate the hidden key from a file that has been exfiltrated from the network. 

## Part 2

Download the provided binary (`doughmains`) from `challenge.us/files`.

Analyze the binary to understand its functionality. Once you've analyzed the binary, you will be able to use the key from the pcap to run the binary and generate a list of domains. One of these domains will be the correct answer.

## Part 3

Connect to the the `escalate` machine and find a way to gain root access. 

You may need the wordlist (`wordlist.txt`) from `challenge.us/files` to assist you with this task. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|
|escalate [10.5.5.101]|user|tartans|

## Submissions

**Question 1**: Using `dga.pcap`, what is the key string obtained by identifying and opening the file that was exfiltrated from the network? 

**Question 2**: What is the value of the token you receive by running the Grading Check at `challenge.us` and submitting the domain listed on the 14th line from the output of the `doughmains` binary?

**Question 3**: What is the value of the token found in the home directory of the root user on the `escalate` machine?

## Notes

- **dga.pcap**: The provided packet capture containing the hidden key.
- **doughmains**: The provided binary that generates a list of domains.
- **wordlist.txt**: The provided word list to assist with password cracking attacks.
  
Please refrain from unauthorized access to any systems outside of the provided challenge files. Use the Kali Linux machine and the tools provided to interact with the challenge files and solve the puzzle.
