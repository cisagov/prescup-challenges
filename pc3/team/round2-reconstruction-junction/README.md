# Reconstruction Junction

Analyze a set of pcaps to reconstruct exfiltrated data

**NICE Work Roles**

 [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

 [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework) - Capture and analyze network traffic associated with malicious activities using network monitoring tools.

- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework) to identify possible threats to network security.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc3/team-round2-reconstruction-junction-largefiles.zip)
and extract in _this directory_ to get started.

## Background

A park's service has recently come to suspect that secret proprietary data regarding the building of a new monument has been exfiltrated from its headquarters office by malicious insiders. It is unclear how many users are involved and what departments they belong to. Review the most recent rotation of traffic logs/pcap files taken less than an hour ago with one from each of the three(3) major departments.

## Getting Started

Investigate these captures to discover any possible means of data exfiltration, recover the data, and reassemble any disassembled pieces to find the original contents.

NOTE: Only one form of exfiltration will be used in each packet capture and exfiltration methods will not be repeated between capture files. The challenge consists of three(3) parts that can be worked independently from each other.

## Answers
Each section's answer is a 12-character hexadecimal string (6 bytes in length).

## Hints
Anomalous or outlier traffic should be considered suspicious.
All relevant data will be sent in plaintext or within readable packet data (no decryption will be required).
Plaintext communication protocol channels may also be utilized by the insiders.
