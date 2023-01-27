<img src="../../pc1-logo.png" height="250px">

# Are My Control Systems Isolated?
#### Category: Security Provision
#### Difficulty Level: 250
#### Executive Order Category: Cyber-Physical Systems

## Background

You are a cyber security analyst assisting your organization in assessing the state of their Building Automation System
(BAS) network. This system uses protocols which are known to be insecure and therefore, a decision was made to isolate
this network from the rest of the enterprise. However, recent anomalies in system operation have triggered a security
audit and it was discovered that an intrusion took place.

## Getting Started

You have been provided with a packet capture taken from your organization's network sensor infrastructure. Analyze this
PCAP to identify the ICS/SCADA protocol used by the building automation system. All of the traffic should be contained
in the single class C address block of 10.0.0.0/24. An attacker entered this IP space and started interacting with
Programmable Logic Controllers (PLCs) in this network.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc1/individual-round1-sp-0250-largefiles.zip)
and extract in _this directory_ to get started.

## Find the Flag

The attacker read a 4-digit code from Register 3 in one of the PLCs. Report the value of this 4-digit code (for example:
`1234`) as the flag to solve this challenge.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
