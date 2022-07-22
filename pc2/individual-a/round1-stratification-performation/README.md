# Stratification Performation

This challenge is aimed at testing your knowledge of writing YARA rules and disseminating malware obfuscation techniques. In this challenge you are presented with file banks where you must use YARA to scan and find indicators of compromise and report which files they exist in.


  **NICE Work Role:**

  - [Cyber Defense Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

  - [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber%20Defense%20Incident%20Responder)


  **NICE Tasks:**

  - [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

  - [T0278](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0278&description=All) - Collect intrusion artifacts (e.g., source code, malware, Trojans) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

  - [T0175](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0175&description=All) - Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation) tasks to support deployable Incident Response Teams (IRTs).

  - [T0163](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0163&description=All) - Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.

## Background
In this challenge you are provided a series of files, that have been extracted from a recent cyber security incident. Your objective is to write YARA rules to find three files containing different indicators of compromise. 

## Getting Started
The files located in the [challenge directory](challenge/) were provided to challenge participants. To complete this challenge you must install YARA on your platform of choice and write simple rules to scan the three included directories.

Each of the provided folders contains library of files extracted from a recent investigation. The folders correspond to each IOC that you will target with your YARA rules. Once your rule is created, you can run a scan by referencing it as a parameter with yara64.exe. Additionally, you will find that the threat actor who created the files also placed in some obfuscation techniques to obscure commands in each file. Each folder on the disk corresponds with IOCs listed in the table below.

## Indicators of Compromise
| folder       | IOC                                                        |
|--------------|------------------------------------------------------------|
| /IP          | 164.240.138.239                                            |
| /DNS         | hvOiwETMXmzgAfcGrqlHUCQIyVDBbpoJZdKYPensxruNtaLSjFkW.com   |
| /CODE        | rCvAfWxe.exe                                               |

## Submission Format
The answer to each part of this challenge is the **filename** that matches the indicated IOC.
