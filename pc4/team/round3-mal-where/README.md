# Mal-where?

They've been attacked. The infrastructure had several tools installed, but nobody optimized them for the environment! If you're not prepared when the rain comes, it's too late. We're in the mud now. Can you figure out what happened to the infrastructure with only these stock defense tools in your toolbox?

**NICE Work Roles** 

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-incident-responder)

**NICE Tasks**

- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0161) - Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system (IDS) logs) to identify possible threats to network security.
- [T0278](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0278) - Collect intrusion artifacts (e.g., source code, malware, Trojans) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## IMPORTANT

This challenge does not have any downloadable artifacts. The full challenge can be completed on the hosted site.

## Background

You have been called in to investigate an incident that occurred in early November 2022. This small work center had a centralized Wazuh manager and deployed agents on each hosts; however, they did not configure file integrity monitoring, active defense, or any other non-default functionality. They also had PolarProxy for outbound TLS decryption; however, they did not attain the correct sessions/data limit. Furthermore, they had a default squid web proxy and also had a basic tcpdump capture occurring on the same host as the squid web proxy. Lastly, it appears the squid & tcpdump machine may be out of disk space. This organization had the right ideas; however, let's first help them with this incident and then help their defense posture on a later date.

You have been given console access to each of these machines. The only things that were removed were web and bash history. The organization was not planning on handing over the user workstations; however, they were informed that they may have been part of the incident and may have remnants of the incident left over. 

The organization has removed all internet access to this network (thus some internal web pages may appear wonky). We cannot change the cards we are dealt, just how we play the game.
  
## Topology

![c48-1640409047.png](https://Launchpad.cisa.gov/tm/docs/b9f73c5d50b04a7d996f46df8468b01e/c48-1640409047.png)

## Getting Started

- Task 1: Discover the malware that was utilized to gain internal access to a user workstation
- Task 2: Discover the IP address of the C2 server involved after the malware was planted and executed
- Task 3: Discover the attacker that was inside your network based on artifacts left behind

## Challenge Questions

1. Who is the author of the malware?
2. What is the IPv4 address of the C2 server?
3. Who was the attacker that was inside your network and left something behind?
