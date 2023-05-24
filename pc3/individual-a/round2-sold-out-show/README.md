# Sold Out Show

DC has been compromised by a golden ticket attack.

**NICE Work Roles:**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

    
**NICE Tasks:**  

- [T0187](https://niccs.cisa.gov/workforce-development/nice-framework) : Plan and recommend modifications or adjustments based on exercise results or system environment.

- [T0258](https://niccs.cisa.gov/workforce-development/nice-framework) : Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment. 

## Background
Our DC has been compromised by a golden ticket attack! This is a nightmare! Somehow our hashes were dumped. It was probably because of our laziness, but we're not sure! Please note, this attacker is known for using names not in AD and sets up WMI persistence within the DC. He also uses a custom binary to exfiltrate data. Investigate and hopefully our very important documents are not stolen.


## Getting Started
Log into the DC to look into the attack. I would begin by looking into the event logs.


## Submission Format
Tokens will be spread out through the entire challenge. The tokens are as follows:
- User of the attack

- Find the site they're using to exfiltrate important documents

- Investigate WMI persistence

- Fix the leak of the NTDS.dit file. 
