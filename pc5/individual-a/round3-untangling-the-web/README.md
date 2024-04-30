# Untangling the Web

A personnel device tracking server has gone offline. Perform memory analysis to recover the device asset list, identify a specific user's tracking device on the network, and correlate their network time with other network activities for signs of malicious acts. Some scripting to assist in analysis is required.

**NICE Work Roles**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
- [T0286](https://niccs.cisa.gov/workforce-development/nice-framework): Perform file system forensic analysis.
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework): Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.


## Background

A personnel device tracker server located in the security network (`10.4.4.0/24`) recently crashed in our space ship's network. The server failure left us blind to the location of certain crew members. One of these crew members, Louie, may be a malicious insider attempting to steal data for the Bulborb faction. He might be taking advantage of going unnoticed during this downtime. 

Figure out Louie's device locator tag ID, detect his activities on the net, and then investigate his actions and recover any sensitive data that may have been compromised.

## Getting Started

Retrieve all artifacts from `https://challenge.us/files`. This challenge does not have any grading.

The events occurred on the afternoon of **August 18th, 2023**. Focus your investigation on events occurring during this time frame.

You have access to a single Kali workstation, but also have remote access to any systems you find during your analysis.

## Objectives

Each objective must be completed in sequence.

### Objective 1: Recover the Locator Tag Assignment List from memory

Luckily, a memory dump was taken right before the `Locator Data` server crashed around 12:30 PM on August 18th, 2023. We know the `Device Assignment List` data was loaded into memory at this time and alphabetical characters in the data are obfuscated using a shift cipher. However, numerals and other symbols are left intact.

The data file has the following headings:

|Locator Tag ID|Individual Assigned|Decryption Password|
|--------------|-------------------|-------------------|

Using the memory dump retrieved from `https://challenge.us/files`, recover the `Locator Tag Assignment List` information for Louie's device tag.

### Objective 2: Determine when Louie's locator device came online

Using the information from Objective #1 and the pcapng file retrieved from `https://challenge.us/files`, determine when Louie's locator device came online. All locator device traffic contents are encrypted in its binary form using AES 256 bit encryption.

### Objective 3: Investigate network traffic correlated to the above time and determine the actions taken by Louie

>Note that this objective has two related questions in the submissions.

Based on when Louie's locator device came online, investigate the traffic for more events following its appearance and determine what actions were taken on the network.

Critical systems can be accessed remotely for investigation. User systems are also configured with `auditd` for tracking terminal commands.

## System Tools and Credentials

| system | OS type | username | password |
|--------|---------|----------|--------|
| Kali | Kali | user | tartans|
| All remotely accessed systems | Ubuntu | user | tartans |

## Note

Attacking or unauthorized access to `challenge.us` (`10.5.5.5` or `64.100.100.102`), k3s-server (10.3.3.10), and app-server (10.3.3.3), is forbidden. You may only use the provided webpage to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the Locator Tag ID assigned to Louie?
2. What packet (number) represents the first time the device in question checked in within the overall packet capture?
3. What account (username) was used to access the final system?
4. How many total Minipiks were on hand at the end of expedition day 24?
