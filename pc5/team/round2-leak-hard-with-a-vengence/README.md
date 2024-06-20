# Leak Hard with a Vengeance

Investigate suspicious activity on a compromised network and find all occurrences of data exfiltration.

**NICE Work Role**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework): Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0166](https://niccs.cisa.gov/workforce-development/nice-framework): Perform event correlation using information gathered from a variety of sources within the enterprise to gain situational awareness and determine the effectiveness of an observed attack.
- [T0258](https://niccs.cisa.gov/workforce-development/nice-framework): Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.
- [T0260](https://niccs.cisa.gov/workforce-development/nice-framework): Analyze identified malicious activity to determine weaknesses exploited, exploitation methods, effects on system and information.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

Recently, a merchant was the victim of a cyber attack by an enemy guild. His ship's systems are up and running again, but he noticed some anomalous activity and believes he is still infected. Help the merchant find all occurrences of data exfiltration.

## Getting Started

Log into the Kali VM and enumerate the ship's network. Below is information about various machines on the network:

| Service/Machine | IP |
| :-------------: | :-------: |
| Website | 10.7.7.7:5000 |
| Security Onion Web Console| 10.4.4.4 |
| Pfsense | 123.45.67.89 |
| K3s | 10.3.3.10 |


## Challenge Questions

1. How many accounts is the financial data being exfiltrated to?
2. What is the value stored in the password_hash field of the users table for the user that is connected to the exfiltrated file data? You do not need to crack the password hash. Provide the value that is stored in the database. 
3. Find and decode the token being exfiltrated via DNS.
4. What is the token that is found with the data that is tracking and exfiltrating user actions?
