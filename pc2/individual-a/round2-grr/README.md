# Grr... 

Remotely triage and clean an infected system.

**NICE Work Roles:**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks:**
- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework).

- [T0397](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform Windows registry analysis.

- [T0432](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise

<!-- cut -->

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment. 

## Background
You're provided remote access to an infected system via GRR Rapid Response.  There is a rogue process named `wmpupdate.exe` running on the system.

## Getting Started
Your first task is to perform remote live forensics of the infected system using GRR Rapid Response and determine the indicators of compromise associated with the rogue process. For this task, you'll be graded on the following questions. 

Q1. Where is the process executable located on the disk?

Q2. What is the autorun registry key associated with the rogue process?

Q3. Provide the `Name` of the firewall rule associated with the rogue process.

Your next task is to utilize the IOC information and remotely clean the infected system, again via GRR Rapid Response. For this second task, you will earn points if -

Grading Check 1 - Rogue process is stopped

Grading Check 2 - Process executable is deleted

Grading Check 3 - Autorun registry key associated with the rogue process is deleted

Grading Check 4 - Firewall rule associated with the rogue process is deleted (not just disabled)

A grading script is executed every 2 minutes and the results are published to `http://192.168.10.102`.

Please note -
* The Grading results URL (`http://192.168.10.102`) and GRR Web Console (`http://192.168.10.100:8000`) are both accessible from the `Analyst` VM.
* The hostname of the infected system is `WIN-GRR-01`.
* The GRR client is installed on the infected system and is reporting to the GRR server.
* Try using the browser level refresh button if at times  the directory listing does not appear even after using the refresh button within the `GRR Virtual Filesystem`.

## System and Tool Credentials
| system/tool | username | password |
|-------------|----------|----------|
| Analyst  | user     | tartans  |
| Grr-Server     | user     | tartans  |
| Grr-Server Web Console       | admin    | tartans  |
