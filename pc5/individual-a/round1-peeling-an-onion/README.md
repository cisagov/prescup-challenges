# Peeling an Onion

Respond to, and investigate, a network attack scenario.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.
- [T0036](https://niccs.cisa.gov/workforce-development/nice-framework/): Confirm what is known about an intrusion and discover new information, if possible, after identifying intrusion via dynamic analysis.
- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation) tasks to support deployable Incident Response Teams (IRTs).
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework/): Capture and analyze network traffic associated with malicious activities using network monitoring tools.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.


## Background

One of your web servers is being attacked. The machine is isolated from the network to prevent lateral movement, and there is a Security Onion instance monitoring the traffic at the switch.  Investigate the alerts and answer questions about the attack.

## Getting Started

Login to Security Onion (`http://10.4.4.4`) and perform a traffic capture. The sensor ID for Security Onion in your environment is `securityonion`.  Use the provided wordlist CDROM, located in your Kali VM's Desktop, for any required password cracking. 

The Security Onion machine may take up to eight minutes to become available--**please be patient!**

## System and Tool Credentials

| system/tool | username | password |
|-------------|----------|----------|
|analyst-machine|user    | tartans  |
|securityonion web interface 10.4.4.4 | admin@so.org | tartans@1|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge questions

1. What is the IP of the machine that performed a SQL Injection attack?
2. What is the IP of the machine that successfully brute-forced the website login?
3. The database has been exfiltrated from the site.  What is the insecure password that's been used for multiple administrator accounts?
