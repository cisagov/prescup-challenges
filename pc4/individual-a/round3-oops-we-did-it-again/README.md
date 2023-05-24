# Oops! ...we did it again

During a *Dauntless* docking period, malware downloaded from one of several potentially malicious domains was detected. Based upon new information, it appears that a *second* compromise may have occurred.

Investigate network traffic to trace activity, analyze and remove malware, apply recommended mitigations, and recover lost data.

**NICE Work Roles**
 - [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)
 - [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
 - [T0161](https://niccs.cisa.gov/workforce-development/nice-framework) to identify possible threats to network security.
 - [T0175](https://niccs.cisa.gov/workforce-development/nice-framework).
 - [T0278](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## Background

Investigate malware on a compromised system on *Dauntless*. All relevant data has been made available in-game at: `http://challenge.us/files`. Please be patient; it may take a few minutes before the site is available.

## ⚠️ Large Files ⚠️

This challenge includes large files as a separate download. Please [download the required pcap file](https://presidentscup.cisa.gov/files/pc4/individuala-round3-oops-we-did-it-again-largefiles.zip) to get started. The zipped file is ~203MBs and the extracted pcap is ~222MBs.

## Getting Started

_Note: Please follow the instructions in the [challenge directory](./challenge) before starting this challenge offline._

The compromised system has been moved to a semi-isolated network for analysis with an IP address of `64.100.100.100/2`.

The Kali VM is connected to the same in-game network as the compromised system via interface **eth1**, though you will first need to provide the necessary interface configuration (e.g. `sudo ifconfig eth1 64.100.100.105/2`). Once configured, you can connect to the compromised system and investigate and view the same websites used in the packet capture.

To successfully solve this challenge:

1. Determine how the malware got on the system.
2. Determine the type/variant of the malware.
3. Remove the malware and perform recommended mitigations on the grading page. (Make sure you have all necessary information on the malware before permanently removing it. You can destroy and restart the challenge to return to an earlier state.)
4. Recover the lost data on the compromised system.

Start by analyzing the network traffic packet capture. We believe the target data resides in TLS/HTTPS encrypted traffic. An overzealous IT manager has admitted to collecting pre-shared SSL keys through a persistent environment variable on all user systems.

## Grading

Navigate to `https://challenge.us` from a gamespace resource to view the mitigation tasks/status. The grading check will take a moment to complete. Please refresh the grading page after 10-15 seconds to get your results.

The grading check queries the compromised system from an IP address of `64.100.100.102`. **Do *not* disable or modify the networking of the compromised machine or interfere with network traffic needed for grading. If you do, the grading system will not work.**

## Challenge Questions

1. What is the IP address associated with the website that hosted the unique malware package that was downloaded only once over the network?
2. What is the type and version/variant of the rootkit found on the compromised system?
3. What is the token string provided by the challenge server for successfully removing the malware?
4. What is the flag/token recovered from the decrypted contents of the ransomware encrypted files?
