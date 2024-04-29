# Protect Ya Tech

Investigate a packet capture for evidence of programmable logic controller (PLC) device tampering and secure the network of *Daunted*, an Aurellian spaceship, to prevent further tampering.

**NICE Work Roles**

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
- [T0163](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.


## Background

Someone on the Aurellian spaceship *Daunted*'s network has been tampering with a PLC device on the supervisory control and data acquisition (SCADA) systems by updating its register with fake data. Analyze the provided traffic capture, identify the host the threat actor accessed the PLC from, what values they updated, and remediate the vulnerability.  

The SCADA system is on the `10.1.1.0/24` and `10.2.2.0/24` networks. Therefore, the PLC device **should only receive Modbus/TCP traffic** from those networks.

## Getting Started

On the Kali VM Desktop, open the `capture1.pcapng` file. Analyze the capture to answer the questions. After answering Question 1 and Question 2, change the network to prevent unauthorized Modbus traffic. 

## Grading

In the gamespace, browse to `challenge.us` and click the **Grade Challenge** button when you are ready to answer Question 3.

**Grading can take 1 - 3 minutes. Please be patient!**

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|
|Pfsense (https://10.0.0.1)|user|tartans|
|plc-poll|user|tartans|
|plc-slave|user|tartans|
|VyOS router|vyos|vyos |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the IPv4 address of the host that wrote unauthorized entries to the PLC?
2. What are the new updated values stored in the PLC registers by the unauthorized host in Question 1? Enter without spaces in the order they were received.
3. Prevent the PLC device from receiving Modbus/PLC traffic from a network other than `10.1.1.0/24` or `10.2.2.0/24`. After securing the network from further PLC tampering, enter the token given by the grading check after visiting `https://challenge.us` in game.
