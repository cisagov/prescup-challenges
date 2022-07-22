# I Thought I Checked That

Given a Linux binary executable file, you must craft an exploit which prints the submission token.


  **NICE Work Role:** 
  
  [Exploitation Analyst](https://niccs.us-cert.gov/workforce-development/cyber-security-workforce-framework/workroles?name=Cyber%20Defense%20Incident%20Responder)


  **NICE Tasks:**  

  [T0641](https://niccs.us-cert.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0641&description=All) - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.  

  [T0736](https://niccs.us-cert.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0736&description=All) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## Background

You are given a vulnerable Linux binary executable file. You must exploit the program and change execution to call the function which prints the token.


## Getting Started

You are provided a [challenge.elf](./challenge/challenge.elf) binary file along with this challenge. Exploit the program to get it to call the function which prints the token.


## Submission Format

The token you submit is a 32 character alpha-numeric string.

## Note
The source code for the binary is provided in the [vuln.c](challenge/vuln.c) file, as well as a [script to compile the source code](challenge/compile.sh). These files are provided as part of open sourcing, but were not provided to the competitors during the competition. Looking at these files may give away answers to the challenge. 
