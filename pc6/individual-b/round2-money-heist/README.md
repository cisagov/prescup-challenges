# Money Heist

Analyze a custom UDP protocol and perform a spoofing attack. 

**NICE Work Roles**
* [Cyberspace Operations](https://niccs.cisa.gov/workforce-development/nice-framework)
* [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
* [T1668](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct network scouting
* [T1669](https://niccs.cisa.gov/workforce-development/nice-framework): Analyze system vulnerabilities within a network
* [T1013](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct technical exploitation of a target

## Background

You are tasked with conducting a security audit on a custom protocol used by a new banking startup for communication between an ATM and the central bank server. 

## Getting Started

There is an ATM server running on `10.1.1.50` and an ATM client running on `10.2.2.50`. They are communicating with each other via UDP on port 3200. The communication between the ATM server and client is happening on separate networks from your `kali` machine, so you will not be able to reach these IP addresses. 

You can use **Security Onion** to create PCAP files and view the traffic between the client/server. You can do this by logging in to the `securityonion` device directly and creating a packet capture by listening on the `tap0` interface. 

The ATM server has a second network interface which is connected to the same network as your `kali` machine. You can access the ATM server from your `kali` machine at `10.5.5.101`. 

A description of the packet specification can be found at `challenge.us/files/spec.txt`

Note: SSH is open on the ATM server and client, but those services are not in scope for this challenge.

## Submissions

**Token #1**: Intercept the communication between the ATM server and client to determine the cash balance of account `1827307999`. Once you are able to do so, run the Grading Check at `challenge.us` to receive your token. 
 
**Token #2**: Craft your own packet to query the ATM server and determine the cash balance of account `2097954097`. Once you are able to do so, run the Grading Check at `challenge.us` to receive your token. 

**Token #3**: Craft a spoofed packet to the ATM server appearing to come from the ATM client (`10.2.2.50`) to transfer all of the money from account `1869589436` to account `1320571932`. Once you are able to do so, run the Grading Check at `challenge.us` to receive your token. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|
|securityonion|so|tartans|
|atm-server [10.5.5.101:3200]|||


## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
