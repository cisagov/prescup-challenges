# Cosmic Code Crackers

Investigate systems and IDS logs in order to locate, detect, analyze, reverse engineer, and exploit various malicious or suspicious programs and related activities.

**NICE Work Roles**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
- [T0182](https://niccs.cisa.gov/workforce-development/nice-framework): Perform tier 1, 2, and 3 malware analysis.
- [T0286](https://niccs.cisa.gov/workforce-development/nice-framework): Perform file system forensic analysis.
- [T0432](https://niccs.cisa.gov/workforce-development/nice-framework): Collect and analyze intrusion artifacts (e.g., source code, malware, and system configuration) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

<!-- cut -->

## Background

The ship network has been compromised by malicious code! Some files may contain sensitive data--investigate these suspicious files and reverse engineer or crack the code to gain access. *Cosmic Code Crackers* is comprised of several parts. Each part can be solved independently and simultaneously by a team.

## Getting Started

Note that `challenge.us` inside the gamespace may take a few minutes to load as the challenge environment is prepared.

Kali comes pre-equipped with several reverse engineering and code analysis tools. A GUI-friendly debugging tool, Cutter, is available at `challenge.us/files` from a gamespace browser. The Cutter AppImage file can be run on Kali as a standalone application after downloading it and marking it as executable.

You may also wish to install tools on Kali like Wine, xxd, OllyDbg, or EDB-Debugger using `apt install` from the Kali system.

## Objectives

**Part 1: Analyze and exploit the suspicious file found on the User-A network client**

- Determine the location of the suspicious file present on the User-A network client at `10.1.1.50`. See log data on  `securityonion` at `/var/ossec/logs/alerts/alerts.log`.
- Analyze the file.
- Force it to provide the "secret" via buffer overflow. *Note: The secret is contingent upon exploiting the malware on the User-A-Client system; disable ASLR with the command:* `echo "0" | sudo tee /proc/sys/kernel/randomize_va_space`.
- Use the secret information to find the location of the token on the client system.

**Part 2: Reverse engineer the suspicious file found on the User-B network client**

- Determine the location of the suspicious file present on the User-B network client at `10.2.2.50`. See log data on  `securityonion` at `/var/ossec/logs/alerts/alerts.log`.
- Decompile and use the available code to pass the conditions in the program's `crack_ me` function. You don't need to run the program; simplifying in pseudocode and applying what you learn will suffice.
- Use the discovered strings to generate a 5-character username and 10-character password. Decrypt the .zip file found in that user's home directory on User-B using this password.

**Part 3: Analyze Security Onion alerts/logs to identify potential malware**

IDS alerts/logs from today (Last 24 Hours) were seen pointing to potential malware that may have been posting data from an infected client in the User-B network, which has since been taken offline.
- Connect to Kibana on the Security Onion at the webtools address of https://10.4.4.4 and use the credentials `admin@so.org | tartans@1` to login.
- Analyze these alerts and locate any files that were transferred in the IDS data.
- Use VirusTotal (out of game) to analyze the hashes of any files discovered to uncover their true identity.
- Use the provided malware list (**mw-list.csv**) from `challenge.us/files` and information from [VirusTotal](https://virustotal.com) to determine the malware type. You must access VirusTotal outside of the gamespace - i.e. from a browser on your local system.

## System Tools and Credentials

| system | OS type | username | password |
|--------|---------|----------|--------|
| Kali | Kali | user | tartans|
| Clients | Ubuntu | user | tartans |
| SecurityOnion | Ubuntu | so | tartans |
| SO Webtools (`https://10.4.4.4`)| ~ | [admin@so.org]() | tartans@1 |

## Note

Attacking or unauthorized access to `challenge.us` (`10.5.5.5` or `64.100.100.102`) is forbidden. You may only use the provided webpage to view challenge progress and download any challenge artifacts that are provided.


## Challenge Questions

1. What is the return address (in little endian format) that would allow you to overflow the overflow_me function and retrieve the secret information found by analyzing the suspicious file found on the User-A network client?

2. What is the size (in bytes) of the buffer/stack that would allow you to overflow the overflow_me function and retrieve the secret information found by analyzing the suspicious file found on the User-A network client?

3. What is the token found by analyzing the suspicious file found on the User-A network client system?

4. What is the token found by analyzing the suspicious file found on the User-B network client?

5. What is the name of the malware that was used based on the findings from the network traffic logs in SecurityOnion?