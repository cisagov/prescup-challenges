# Let's Go Phishing

To simulate a phishing attack, you will upload malware for a user to execute, then must use your access to the user's machine (via your malware) to escalate privileges and retrieve the tokens.


**Nice Work Role:** 

[Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**    

 [T0028](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct and/or support authorized penetration testing on enterprise network assets.
 
 [T0736](https://niccs.cisa.gov/workforce-development/nice-framework) - Lead or enable exploitation operations in support of organization objectives and target requirements."


## IMPORTANT
This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.


## Background

You have been tasked to conduct a penetration test of the `challenge.pc` domain and associated systems.  The end-goal of this test is to gain access to a standalone machine with the name `Dev` (this machine is not joined to the challenge.pc domain but is part of the company enterprise). 


The `Dev` machine is owned and operated by a user who always forgets their local administrator password. The IT department has made it such that they are able to RDP from the Domain Controller to the user's machine, but this user does not like to wait for the IT department to help her. The user has installed her own backdoor to the system which allows her to reset a forgotten password at any time by taking advantage of the sticky keys hot key.

## Getting Started

You are given Kali VMs to utilize for the assessment.

There is an FTP server on the network at `ftp.challenge.pc`. To simulate a user running a malicious program on their workstation, the FTP site is being polled — any file with a `.exe` extension will be downloaded and run on a domain joined user VM. Any uploaded file will only run for 5 seconds before being terminated. If you wish to upload a file more than once, change the name of the file that is being uploaded.

Use a Kali VM to create a `.exe` which gives you access to the user VM. The user machine will have a token in `C:\\token\\usertoken.txt`. You should then escalate privileges and pivot to the domain controller to view the token in `C:\\token\\dctoken.txt` on the domain controller.  The final token is located at `C:\\token\\devtoken.txt` on the Dev machine. 

## Submission Format
All submission tokens will be 16 character alphanumeric strings (all lowercase). 

The user token will be located at `C:\\token\\usertoken.txt` on the user machine.  
The domain controller token will be located at `C:\\token\\dctoken.txt` on the domain controller.   
The dev token will be located at `C:\\token\\devtoken.txt` on the Dev machine. 

