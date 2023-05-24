# Thanks for Logging Secrets

You must analyze a disk image in order to decrypt HTTPS traffic that contains a token.

**NICE Work Roles:** 

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)  
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework) - Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.  
- [T0259](https://niccs.cisa.gov/workforce-development/nice-framework) - Use cyber defense tools for continual monitoring and analysis of system activity to identify malicious activity.  
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework) for recovery of potentially relevant information."

## IMPORTANT
This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.


## Background
The token resides somewhere in captured network traffic. By using forensic tools to analyze the provided disk image, you can find everything you need to obtain the token.


## Getting Started
You may use either a Windows 10 or a SIFT workstation to complete this challenge. Both workstations have an identical secondary drive mounted named **Image** that contains a packet capture (`https_capture.pcapng`) and a disk image of a Windows 10 machine (`win10-image.001`). 

## Submission Format
The token is a 16-digit hexadecimal number wrapped in the standard President's Cup wrapper of the format `0123456789abcdef`.
