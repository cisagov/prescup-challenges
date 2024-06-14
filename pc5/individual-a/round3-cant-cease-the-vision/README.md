# Can't Cease The Vision

Identify how insiders are sending secret codes.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework): Examine recovered data for information of relevance to the issue at hand.
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework): Capture and analyze network traffic associated with malicious activities using network monitoring tools.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the large files [here](). The packet capture file extracted from the large file zip was captured in the hosted environment. It allows this challenge to be completed outside of the hosted environment. The zipped file is ~224 MBs and the extracted file is ~317 MBs.

## Background

You are employed by a dam in a rural area. The dam has six employees and is closed to the public. The daily revolving 8-digit launch code to open the floodgates has been compromised. Only two employees know the 8-digit code every day; however, it has been found written down in areas of the dam site where these two employees are not authorized to access. Catch the two suspected insider threat actors in the act by finding the most recent (within last 24 hours) 8-digit code being sent over the network.

## Getting Started

Examine the traffic, perform network-based forensics, and discover the hidden 8-digit code that is consistently being sent over the network. Login to **Security Onion** (`10.4.4.4`) and examine the network traffic. The sensor ID for Security Onion in your environment is `securityonion`. 

## Challenge Questions

1. What is most recent (within last 24 hours) 8-digit launch code?
