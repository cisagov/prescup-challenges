# A View to a Spill

Investigate device lists and network traffic to access ship security cameras and confirm evidence of a data leak. Remediate the problem to prevent future leaks.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**
 - [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
 - [T0163](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.
 - [T0166](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform event correlation using information gathered from a variety of sources within the enterprise to gain situational awareness and determine the effectiveness of an observed attack.
 - [T0260](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze identified malicious activity to determine weaknesses exploited, exploitation methods, effects on system and information.
 - [T0298](https://niccs.cisa.gov/workforce-development/nice-framework/): Reconstruct a malicious attack or activity based off network traffic.

## Background

Flaws in the configuration of security cameras used ship-wide have been reported. One ship in the fleet noticed chain codes specific to it were compromised and used to forge transmissions to other ships and stations within the system. *The security team could not find evidence that credentials were exposed or used in the data leak, and that the security.merch.codes website is secure. Some other way of accessing the data must have been unintentionally left open **on the network**.*

## Getting Started

*After the challenge launches, please give it three minutes to initialize before trying to access the downloadable artifacts.*

Given a device list, transmission log, Aurelian/English alphabet, and exemplar pcap data from a ship using the same IP network ranges as our ship, determine if our security cameras are exposing sensitive data due to misconfiguration. Review security footage for evidence of sensitive data being leaked. The camera management web GUI is here: `security.merch.codes`.

Once you have successfully recovered the first token (Submission #1) the final task will be made available.

## Final Task

To get the information for the final task, add the first token string to the **token.txt** file on your Desktop and trigger the grading check at `challenge.us`. If the string is correct, a new file at `challenge.us./files` containing instructions for your final task will appear. 

Subsequent grading checks validate whether you have performed the necessary remediations and provide a new token if successful.

**Data files are available at `https://challenge.us/files`. Conduct all other interactions and activities on the network.**

## System Tools and Credentials

| system | OS type | username | password |
|--------|---------|----------|--------|
| Kali | Kali | user | tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5 or 64.100.100.102) is forbidden. You may only use the provided webpage to view challenge progress and download any challenge artifacts that are provided.
