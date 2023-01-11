## The Threat is Coming From Inside the Ship

Analyze network traffic, intelligence data, and a compromised system in order to identify potential insiders and their activities.

**NICE Work Roles**

 - [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-incident-responder)
 - [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-analyst)

**NICE Tasks**

 - [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0161)- Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
 - [T0175](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0175)- Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation)
 - [T0290](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0290)- Determine tactics, techniques, and procedures (TTPs) for intrusion sets.
 - [T0312](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0312)- Coordinate with intelligence analysts to correlate threat assessment data.

## Background
A recent release of intelligence reports has you worried about malware being potentially downloaded to one of the ship's systems during its last orbital dock. Not only is there a risk to the system, but proper identification of those responsible is necessary to prevent further harm.

Potential malicious domains for hosting malware include:
 - `www.cabindecor.com`
 - `www.denyxenos.com`
 - `www.justxenos.com`
 - `www.nauticalxenos.com`
 - `www.orangeparadise.com`
 - `www.plentyofxenos.com`
 - `www.spacedout.com`
 - `www.starshipsandgarden.com`
 - `www.xenosdaily.com`
 - `www.xenobook.com`
 - `www.xenoliving.com`
 - `www.xenomingle.com`
 - `www.xenorealty.com`
 - `www.xenotruth.com`
 - `www.xenosamongus.com`

You must complete the following objectives (in this suggested order) to identify the responsible party:
 1. Review the provided traffic capture file for evidence of a suspicious file being downloaded from one of the malicious domains
 2. Search the potentially compromised system to determine if malware is indeed present. We have intelligence on prior intrusions that suggest the malware was moved to the `/usr/` directory, but aren't sure exactly where it might be now.
 3. Interrogate the system for Indicators of Compromise (IOC's) and compare them to the IOC/threat actor matrix in order to ID the responsible suspect. The system has been removed from the network to reduce the risk of spread.

All challenge related files, a packet capture file and a the IOC/threat actor matrix, can be accessed by browsing to `https://challenge.us/files` from the Kali system. It may take a few minutes for these files to become available.

In addition to these files, you will have direct console access to the compromised system, though be careful not to modify or change the system while you look for IOC's.

## Hints
 - Tasks in this challenge should be completed sequentially so that you have the proper information needed for future tasks.

## Challenge Questions

1. What domain hosted the malware file that was downloaded to the system?

2. What is the obfuscated name of the malware file as it exists on the compromised system (extension is not required)?

3. Which threat actor is responsible for the malware based on the IOC matrix?
