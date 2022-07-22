# Old is Gold

Analyze a forensic image to investigate an incident. 


**NICE Work Role:** 


- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All) 


**NICE Tasks:**


- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0027&description=All) - Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.
- [T0396](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0396&description=All) - Process image with appropriate tools depending on analyst's goals.
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.


## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment. 


## Background

Network operators at your organization have seen some ICMP data exfiltration happening from a particular system in the network. This system has also made a connection to a suspicious IP (`1.66.20.98`). Based on the intelligence data, a well known text editor has been compromised and is responsible for connection to that suspicious IP. 

An Incident responder has imaged the system and the forensic image is available for analysis. According to the incident responder, the text editor in question was running on the system when the system was imaged.

## Getting Started

You are provided with two analyst workstations - Win10 and SIFT. The evidence iso containing the hard drive image (`image.dd`) is attached to both the VMs. The incident responder forgot to acquire memory of the system. 

Your end goal is to analyze the forensic image and answer the following questions.
1. Provide the process ID of the process responsible for connection to the suspicious IP (1.66.20.98).
2. Provide the IP address that received the exfiltrated data.
3. Provide the MD5 of the file that was exfiltrated.
4. Name the executable that the attacker used to cover his tracks (delete other files).
5. What time did the attacker upload the file referenced in the previous question on this system?
6. What was the previous name of this file (The file referenced in the previous two questions)? The filename when it was uploaded to the system by the attacker.

## System and Tool Credentials

| system/tool | username | password |
|-------------|----------|----------|
| analyst-sift   |    user   |  tartans  |
| analyst-win10     |   user    |   tartans |
