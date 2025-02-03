# Exfil Enigma

Help assess a small business's network. Recently, suspicious activity was noticed, and they need your help to identify data exfiltration, potentially compromised machines, and malicious software.

**NICE Work Role**

- [Defensive Cybersecurity](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify anomalous network activity
- [T1347](https://niccs.cisa.gov/workforce-development/nice-framework/): Detect cybersecurity attacks and intrusions
- [T1348](https://niccs.cisa.gov/workforce-development/nice-framework/): Distinguish between benign and potentially malicious cybersecurity attacks and intrusions
- [T1351](https://niccs.cisa.gov/workforce-development/nice-framework/): Determine impact of malicious activity on systems and information

## Background

Use the provided Kali machines to explore the network and identify malicious network traffic, compromised machines, and suspicious software.

## Getting Started

Log in to the `kali-exfil-enigma` VM and use the provided tools to explore and analyze the network. External websites are available on the WAN, located at `123.45.67.89/24`. You can perform packet captures on the pfSense firewall using the Web GUI under the *Diagnostics* tab.

If you use Security Onion to create PCAP files, make sure to enter `securityonion` in the **Sensor ID** field. Log into Security Onion at `10.4.4.4` through a browser or via SSH.

## Submissions

There are five (5) tokens to retrieve in this challenge. All tokens are 8-character hexadecimal strings.

- **Token 1:** Find this token by locating the exfiltrated payroll data.
- **Token 2:** Token 2 is a password protected file. Begin by locating the file in the network traffic. The password is hidden in a separate transmission.
- **Token 3:** Find this token by analyzing the user-workstation VM.
- **Token 4:** This token can be located by examining web related traffic.
- **Token 5:** Locate the password of the user with the username of *p.wheeler* in the exfiltrated database file.
