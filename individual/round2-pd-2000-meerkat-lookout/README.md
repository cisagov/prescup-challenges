<img src="../../logo.png" height="250px">

# Meerkat Lookout
#### Category: Protect and Defend
#### Difficulty Level: 2000
#### Executive Order Category: Cyber-Physical Systems

## Background
You have been assigned to install Suricata IDS from a tarball. This IDS will be utilized to detect unauthorized SCADA traffic.


## Getting Started

**Topology**
<img src="topology.png">


*Please note: During the competition, the entire topology was available to the participants. Their task was to install and configure Suricata IDS on the Suricata system and analyze live traffic in the topology. In this open-source/offline version of the challenge, we are providing you with a pcap file of that traffic. Your task is to install and configure Suricata on an Ubuntu virtual machine and run it against the pcap file.*

**Challenge Flow**

 - Download and install Ubuntu 18.04 
 - Download and install Suricata (suricata-4.0.5.tar.gz)
 - Configure Suricata to detect unauthorized SCADA traffic
    - Set HOME_NET to only be the PLC, HMI, and Firewall's IP addresses (not the entire network)
    - Enable only the following IDS rules:
        - ciarmy
        - emerging-attack_response
        - emerging-dos
        - emerging-exploit
        - emerging-ftp
        - emerging-malware
        - emerging-scada
        - emerging-scan
        - emerging-trojan
        - emerging-worm
        - local.rules
    - Create IDS rules to address the following:
        - Create a rule for any port besides authorized going to PLC. Assign SID 2233001
        - Create a rule for any port besides authorized coming from PLC. Assign SID 2233002
        - Create a rule for HMI reaching out to any device rather than the PLC or HMI's /24 network. Assign SID 2233003
        - NOTE: Traffic to/from PLC's port 502 is authorized
        - NOTE: Traffic to/from HMI's port 80 and 443 is authorized

**Flag Submission**
- Once Suricata is running, find the following information:
    - What non-local.rules SID is being triggered against HMI?
    - What two RFC1918 IP addresses (that is also not located on HMI's /24 network) is the HMI reaching out to?
    - A number of non-approved ports triggered 2233001 and/or 2233002. Which is the lowest of those offending ports?
- Once you have found the four items above, generate your flag consisting of the values in this syntax:
    - [SID]-[lowest IP address]-[highest IP address]-[port]
- Syntax Examples:
    - 2014247-172.16.2.6-172.16.2.7-53
    - 2012943-10.1.21.26-192.168.1.3-80

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.