## The Threat is Coming From Inside the Ship

Analyze network traffic, intelligence data, and a compromised system in order to identify potential insiders and their activities.

**NICE Work Roles**

 - [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)
 - [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

 - [T0161](https://niccs.cisa.gov/workforce-development/nice-framework) to identify possible threats to network security.
 - [T0175](https://niccs.cisa.gov/workforce-development/nice-framework)
 - [T0290](https://niccs.cisa.gov/workforce-development/nice-framework) for intrusion sets.
 - [T0312](https://niccs.cisa.gov/workforce-development/nice-framework)- Coordinate with intelligence analysts to correlate threat assessment data.

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


## ⚠️ Large Files ⚠️

This challenge includes large files as a separate download. Please [download the required pcap file](https://presidentscup.cisa.gov/files/pc4/individuala-round1-the-threat-is-coming-from-inside-the-ship-largefiles.zip) to get started. The zipped file is ~83MBs and the extracted pcap is ~100MBs.


## Getting Started

_Note for playing this challenge offline_

_The Insider virtual machine is not available offline, all relevant files and necessary outputs are included. See the contents of the [challenge directory](./challenge) to retrieve the necessary challenge files._ 
 * _[threatactormatrix.html](./challenge/threatactormatrix.html) - the Threat Actor Matrix file_
 * _[file-system.zip](./challenge/insider/file-system.zip) - a zip file containing the `/usr/` and `/home/user` directories from the Insider's machine_
 * _[netstat-output.txt](./challenge/insider/netstat-output.txt) - output of the `netstat` command from the Insider's machine_
 * _[shadow-file.txt](./challenge/insider/shadow-file.txt) - a copy of the `/etc/shadow` file from the Insider's machine_


You must complete the following objectives (in this suggested order) to identify the responsible party:
 1. Review the provided traffic capture file for evidence of a suspicious file being downloaded from one of the malicious domains
 2. Search the potentially compromised system files to determine if malware is indeed present. We have intelligence on prior intrusions that suggest the malware was moved to the `/usr/` directory, but aren't sure exactly where it might be now.
 3. Interrogate the system for Indicators of Compromise (IOC's) and compare them to the IOC/threat actor matrix in order to ID the responsible suspect. The system has been removed from the network to reduce the risk of spread.

In addition to these files, you will have direct console access to the compromised system, though be careful not to modify or change the system while you look for IOC's.

## Hints
 
 - Tasks in this challenge should be completed sequentially so that you have the proper information needed for future tasks.

## Submission Format

The offline version of this challenge uses the answers provided below with the questions.

## Challenge Questions

1. What domain hosted the malware file that was downloaded to the system?
2. What is the obfuscated name of the malware file as it exists on the compromised system (extension is not required)?
3. Which threat actor is responsible for the malware based on the IOC matrix?
