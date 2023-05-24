
# Getting Away With It

Teams must investigate compromised data and determine what the various malicious actors were able to retrieve by replicating their actions, methods, and techniques.

**NICE Work Roles**
- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0258](https://niccs.cisa.gov/workforce-development/nice-framework) - Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.
- [T0260](https://niccs.cisa.gov/workforce-development/nice-framework) - Analyze identified malicious activity to determine weaknesses exploited, exploitation methods, effects on system and information.
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework) for recovery of potentially relevant information.

<!-- cut -->

## IMPORTANT

This challenge is only partially open sourced. The files in the [challenge directory](./challenge/) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

A network was compromised in various ways by malicious actors looking to discover and exfiltrate secret and proprietary information through various methods. Your team has been called to assess the data that was potentially compromised. Each set of compromised data will include a token or flag contained within to verify that you have found the same data points as the attackers. Your team must conduct, and in some cases, replicate or reverse the same methods that the attackers took themselves. Specific instructions for each task can be found in the PDF file attached below. Each task can be analyzed and investigated independently. The full challenge contains four tasks to analyze and respond to.

The four attack methods appear to be related to:

- SQL Injection (sqlmap scans can take time, so start this task early if you choose to use sqlmap)
- Ransomware
- Unauthorized Samba service access
- Local system exfiltration (forensics analysis required)

A task guide can be found here: 
[Getting Away with It - Challenge Task Guide](./challenge/Getting_Away_with_It_-_Challenge_Task_Guide.pdf)


All relevant attack details and data (logs, files, etc) can be found by downloading the various files from the in-game server at `http://challenge.us/files` (`http://10.5.5.5/files`).

Please allow a few minutes from start for the initialization scripts to complete and load the files mentioned above.

## Note
Attacking or unauthorized access to challenge.us (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Systems/Credentials
| system      | OS type   |  username   | passwd  |
|-------------|-----------|-------------|-----------|
|  Kali  | Kali | user | tartans |
|  Kali-SQL-Injection (2nd NIC can be used to connect to the web server) | Kali | user | tartans |
|  Win10-Forensics  | Windows 10 | user | tartans |

## Hints
Timeline Explorer on the Win10 Forensics system will automatically convert timestamps to UTC, so be aware of this (Timeline Explorer may run faster if you copy the timeline file to the local system versus running it from the CD drive)
