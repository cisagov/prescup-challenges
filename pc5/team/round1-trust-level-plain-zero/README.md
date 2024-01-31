# Trust Level: Plain Zero

The Zero Trust network is losing data. Find the exfiltration. Plain and simple.

**NICE Work Roles**

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-incident-responder)

**NICE Tasks**

- [T0041](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0041): Coordinate and provide expert technical support to enterprise-wide cyber defense technicians to resolve cyber defense incidents.
- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0161): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.

## Background

The environment has a Zero Trust application (`zero.merch.codes`) and a sensitive webserver within the Zero Trust environment (`s7331.merch.codes`). Someone has compromised this environment and knew exactly which files to exfiltrate. Identify which four files are being exfiltrated.

## Getting Started

Login to **Security Onion** (`10.4.4.4`) and examine the network traffic. The sensor ID for Security Onion in your environment is `securityonion`. 


## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali*      |user    |tartans |
|securityonion (web)|admin@so.org    |tartans@1    |
|s7331.merch.codes (web)|user    |UALOisiOuSYmpREstR    |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. Regarding the steel file that was exfiltrated, what are the last THREE digits of the original filename?
2. Regarding the account file that was exfiltrated, what are the last THREE digits of the original filename?
3. Regarding the exchange file that was exfiltrated, what are the last THREE digits of the original filename?
4. Regarding the fingerprint file that was exfiltrated, what are the last THREE digits of the original filename?
