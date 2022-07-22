# Vlad the Inhaler

Multiple users are simultaneously connected to a VPN server, appearing to
access Internet resources from the VPN's IPv4 address pool. You are provided
with a packet capture taken at the VPN operator's upstream ISP, containing
both encrypted tunnel traffic (between clients and the server), as well as
cleartext (between the server's address pool and the Internet at large).
Your job is to identify the IPv4 address of the client who used the VPN to
download an image of "Vlad the Inhaler".

**NICE Work Role:** 
- [Cyber Crime Investigator](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber%20Crime%20Investigator)
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber%20Defense%20Forensics%20Analyst)

**NICE Tasks:**
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0240&description=All) - Capture and analyze network traffic associated with malicious activities using network monitoring tools.
- [T0433](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0433&description=All) - Conduct analysis of log files, evidence, and other information to determine the best methods for identifying the perpetrator(s) of a network intrusion or other crimes.

## Background

Multiple users are simultaneously connected to a VPN server, appearing to
access Internet resources from the VPN's IPv4 address pool. You are provided
with a packet capture taken at the VPN operator's upstream ISP, containing
both encrypted tunnel traffic (between clients and the server), as well as
cleartext (between the server's address pool and the Internet at large).
Your job is to identify the IPv4 address of the client who used the VPN to
download an image of "Vlad the Inhaler"
(*Hint: search `images.google.com` for a visual clue*).

***NOTE***: The IPv4 address of the VPN server is `12.0.0.54`, and each VPN
client is allocated a pool addresses from the `128.2.149.0/24` range.

## Getting Started

The provided pcap file (`inhaler.pcap`) contains packets captured
during the attack period. You must identify the IPv4 address of the VPN
user who downloaded an image file representing "Vlad the Inhaler".

***NOTE***: this is ***not*** the pool address allocated by the VPN service
(in the 128.2.149.0/24 range), but rather the end-client-side IP address
used to originate the VPN connection!
