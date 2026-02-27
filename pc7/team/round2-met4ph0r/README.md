# M3t4ph0r

PeanutCo's internal systems have been compromised, and sensitive data has been exfiltrated. 
The company is seeking to understand the extent of the breach and identify the vulnerabilities that were exploited. 
As a security analyst, you have been tasked with conducting a thorough penetration test and providing recommendations for remediation.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analyst](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0280](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify and validate vulnerabilities in the system.
- [T0653](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify and recommend methods for exploiting target systems.
- [T0269](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct exploitation of targets using identified vulnerabilities.
- [T0650](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct target and technical analysis of systems and vulnerabilities.


## Background

Late last night, their Security Operations Center detected encrypted outbound traffic from an internal knowledge management server to an unknown offshore IP address. Minutes later, archived R&D documents related to a proprietary bio-engineered peanut strain began appearing for sale on a dark web marketplace.

PeanutCo’s executive board has authorized a controlled internal penetration test to simulate the breach path and determine:

- How initial access was gained
- How lateral movement occurred
- What vulnerabilities enabled data exfiltration
- Whether persistence mechanisms remain active

Preliminary logs suggest the attacker may have pivoted between systems using misconfigured service trust relationships and vulnerable web components.

## Objectives

Your role is to 
- Emulate the attacker’s path
- Validate exploited weaknesses
- Document the technical chain of compromise.

Each stage of your assessment will yield a secure verification token.

## Tokens

### Formatting

Please review the `placeholders` in the Question section (per task) to determine the correct format of tokens presented.

## Getting Started

Begin by performing reconnaissance operations against the host named `m3t4ph0r`.

## System and Tool Credentials

This table documents the service hostnames and any pre-provided credentials.

|system/tool|hostname|username|password|
|----|---|---|----|
|kali|`kali`|user|password|
|m3t4ph0r|`http://m3t4ph0r`|N/A|N/A|

## Note

Do not attempt to attack or breach the Challenge Platform. You may only perform the tasks assigned on the provided scope.
