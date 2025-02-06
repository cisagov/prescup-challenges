# I Spy: A Digital Intruder

Your company's network has been compromised. They have asked you to analyze one of the local user workstations to identify malicious software and suspicious documents.

**NICE Work Roles**

- [Incident Response](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Defensive Cybersecurity](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify anomalous network activity
- [T1250](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform cyber defense incident triage
- [T1085](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify potential threats to network resources
- [T1347](https://niccs.cisa.gov/workforce-development/nice-framework/): Detect cybersecurity attacks and intrusions
- [T1388](https://niccs.cisa.gov/workforce-development/nice-framework/): Isolate malware

## Background

Use the provided `kali-user-ispy` machine to examine the compromised user workstation (`compromised-host-ispy`) and identify malicious artifacts. You also have direct console access to the `compromised-host-ispy` workstation.

## Getting Started

Login to the `kali-user-ispy` VM and use the provided tools to explore and analyze the compromised host. `AvaloniaILSpy` and `zbar-tools` have been installed on the `kali-user-ispy` VM. Any binaries discovered as part of your investigation should be considered safe to run or analyze freely on your Kali workstation.

If you use **Security Onion** to create PCAP files, make sure to enter `securityonion` in the `Sensor ID` field. Log into Security Onion at `10.4.4.4` through a browser or via SSH.

## Challenge Questions

1. What is the md5 hash of the fschecker file?
2. What is the value of the network beacon being transmitted by fschecker on the compromised host?
3. What is the embedded passphrase used by the chk2.dll?
4. What is the Bitcoin address located in the remote file that is referenced in one of the documents?