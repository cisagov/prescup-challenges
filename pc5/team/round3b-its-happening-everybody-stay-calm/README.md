# It's Happening, Everybody Stay Calm! 

A live attack is happening! Monitor alerts to identify the source of the attack and eradicate it. Be sure to keep logs so you can locate the attacker. 

**NICE Work Roles**

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Cyber Defense Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**
- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.
- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework/) : Decrypt seized data using technical means.
- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework/): Examine recovered data for information of relevance to the issue at hand.
- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation) tasks to support deployable Incident Response Teams (IRTs). 


## Background

A live attack has been detected on our Kubernetes cluster. Luckily, we've recently established a new monitoring service designed to notify of any unauthorized activities within the cluster. This attack comes a few days after we expanded our cluster by adding a new node at `10.3.3.11`, aiming to optimize our system's performance. It's likely the attack initiated from this new node.

Take action immediately: stop this attack and pinpoint its location.

## Getting Started

Falco, a new cluster-monitoring service within our Kubernetes cluster, is configured to send alerts concerning potential unauthorized actions within the cluster to Mattermost. Five Mattermost accounts have been created for you allowing you to receive and review these alerts.

The attack will begin approximately three minutes after starting the challenge. Please be patient.

Use these alerts as the starting point for your incident response duties. Focus on detecting and eradicating the attack, including any signs of persistence. Gather information about the attack as you troubleshoot. This data enables your team to perform forensic analysis of the attack in hope of discovering the attacker's location.

For grading purposes, this challenge is split in two parts. 

**Part 1:** The first part focuses on incident response. Once you have collected any useful data, stopped the attack and removed any signs or persistence, go to `challenge.us`, enter "Initiate" into the top text box and click **Submit**. This initiates grading for both parts. 

**Part 2:** The second part is focuses on digital forensics. Once you have  identified the attacker's location, go to `challenge.us`, enter the location into the bottom text box and click **Submit**. This initiates grading for both parts. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|stay-calm-kali|user|tartans|
|k3s-server (10.3.3.10)|user|tartans|
|k3s-client (10.3.3.11)|user|tartans|

### Mattermost Credentials

|application|username|password|
|-----------|--------|--------|
|https://chat.merch.codes|analyst1|tartans|
|https://chat.merch.codes|analyst2|tartans|
|https://chat.merch.codes|analyst3|tartans|
|https://chat.merch.codes|analyst4|tartans|
|https://chat.merch.codes|analyst5|tartans|

### Other Application Credentials

|application|username|password|
|-----------|--------|--------|
|https://mail.merch.codes|analyst1@merch.codes|tartans|
|https://mail.merch.codes|analyst2@merch.codes|tartans|
|https://mail.merch.codes|analyst3@merch.codes|tartans|
|https://mail.merch.codes|analyst4@merch.codes|tartans|
|https://mail.merch.codes|analyst5@merch.codes|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. After viewing Mattermost alerts, identify and eradicate the attack, including any sign of persistence. Upon completing these steps, initiate system check for automatic grading.
2. Once you stop the attack, analyze the gathered data to identify the attacker's location. Enter the found coordinates here.
