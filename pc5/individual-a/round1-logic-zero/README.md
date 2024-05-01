# Logic Zero

Someone is breaching your zero trust environment. What is going on?

**NICE Work Role**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0166](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform event correlation using information gathered from a variety of sources within the enterprise to gain situational awareness and determine the effectiveness of an observed attack.
- [T0258](https://niccs.cisa.gov/workforce-development/nice-framework/): Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.

## Background

The  environment has a zero trust application (`zero.merch.codes`) and a webserver (`files.merch.codes`) containing sensitive NFT artwork ideas. Someone has compromised this environment by using weak credentials. Someone had a 4 hexadecimal (0-9, a-f (lowercase)) character password!

## Getting Started

No one knows the password to  `zero.merch.codes`; however, console access is given. Begin examining the zero trust environment. The attack is happening now. 

***Warning! Do not remove any network connections.***

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali*      |user    |tartans |
|securityonion (web)|admin@so.org    |tartans@1    |
|webserver|user    |tartans    |
|pritunl (console)|user    |tartans    |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What agent's account was compromised? Only enter the three digits.
2. What was this agent's weak password that was compromised?
3. What is the filename, not extension, of the web resource utilized to gain initial access?
4. What is the Epoch time (UTC) when the system is set to destroy itself?
