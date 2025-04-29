# Ransomware Rhapsody

⚔️ **Please wait five minutes before starting the challenge**

💀 In this challenge, challengers have stumbled upon a compromised system containing a collection of encrypted files. The adversary, in a bashful and hasty fashion, made a critical error on their exit. Your mission is to investigate the remnants of their work and let them know you're on to them.

**NICE Work Roles**
* [Digital Forensics](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics)
* [Incident Response](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/incident-response)
* [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/exploitation-analysis)

**NICE Tasks**
* [T0108](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis of the incident to identify the affected systems, networks, and potential perpetrators.
* [T0115](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze collected information to identify vulnerabilities and leverage them to achieve objectives.

## Background
A crime syndicate called "The w4Nt3D" has infiltrated a corporate network. The asset challengers will have access to has been isolated and acts as the only point of access for triage.

As a Rapid Response Team (RRT), you and a team of incident responders and threat hunters are tasked to:
* Investigate the compromised system for encrypted corporate files
* Decrypt the associated files using any discovered encryption keys sets 
* Investigate the decrypted files to find a key used to communicate with the W4nt3D
* Execute the beacon to let them know you're on to them

## Getting Started

To begin, run the following command `ssh user@10.6.185.57` using the password `tartans` from the `kali-rrt` workstation begin the challenge.

## System and Tool Credentials

|system | operating system | username|password|
|-----------|--------|--------|--------|
|kali-rrt | Debian |user|tartans|
|corp-ubus-24lap (victim) | Ubuntu 22.04 | user | tartans |

**[IMPORTANT]** SSH into `10.6.185.57` with the `user credentials` to begin.

## Intelligence Brief

The Intelligence Community (IC) has recently released a light version of a dossier on "The w4Nt3D".  Details below:


| Category    | Data |
| -------- | ------- |
| <b>Leader</b> | xCh4$3x    |
| <b>Known Members</b> | 36     |
| <b>Last Known Location</b> | Paris, France    |
| <b>Tactics</b> | The syndicate involved with this cyber event is named "The w4Nt3D". Be on the look out for any artifacts or references to this. They are notorious for <ins>hiding</ins> their payloads and malware <b>in plain sight</b> for the thrill of being chased by authorities and to mock their victims. They tend to play games with their victims in order to illicit a response from them.   |
| <b>Signature</b> | This syndicate has a tendency to put short form variants of their name in critical files on their victim's machines.  |
| <b>Slogans</b> | In primary communications, they often use slogans and "L33T Speak". |

## Tactics, Techniques and Procedures
* This syndicate will occasionally concatenate stolen tokens to create a master key that operators can use to `call home`.

**[IMPORTANT] NOTE**
Attacking or unauthorized access to `challenge.us` (10.5.5.5) is **forbidden**. 
Additionally, the `deployer` user is **not in scope** for this engagement. To complete this challenge, root is not required.