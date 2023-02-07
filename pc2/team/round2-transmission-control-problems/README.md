# Transmission Control Problems

You must analyze PCAP files to answer questions regarding the perpetrator of network actions that are impacting overall network performance.

**Nice Work Role:**

- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Network+Operations+Specialist&id=All)

**NICE Tasks:**
- [T0081](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0081&description=All) - Diagnose network connectivity problems  
- [T0153](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0153&description=All) -  Monitor network capacity and performance"

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc2/team-round2-transmission-control-problems-largefiles.zip)
and extract in _this directory_ to get started.

## Background
You are attempting to diagnose several network situations by looking at packet captures. The situations are described below:

**SYN Flood** - A SYN Flood occurs when an attacker takes advantage of the TCP 3-way handshake by sending a large number of SYN packets to a victim in an attempt to overwhelm the system's resources [1]

**Port Scan** - A port scan occurs when an attacker sends packets to a selection of ports on a host to determine which ports are open [2]

**Shrew Attack** - The Shrew attack is a low-rate Reduction of Quality attack which takes advantage of the congestion control mechanisms TCP has in place [3]

**Unencrypted Traffic** - Several TCP protocols send unencrypted data. By sending data "in the clear", the data in the packets is subject to being sniffed/analyzed by other nodes on the network. 

Research papers which discuss the first three of the above scenarios are referenced below and are [available as a PDF](challenge/ResearchPapers.pdf). 

## Getting Started
There are four packet capture files to analyze. 

Each pcap is titled with the name of the attack to look for in that file. You should only be looking for the indicated type of network activity. 

In `synflood.pcapng`, you should be looking to find the IP address of the node performing the SYN Flood as described above and in [1].

In `nmap_scan.pcapng`, you should be looking to find the IP address of the node performing a port scan as described above and in [2].

In `shrew_attack.pcapng`, you should be looking to find the IP address of the node performing a Shrew Attack as described above and in [3]. In this file, the IP address performing the attack does not have any other benign traffic (i.e. that node is only performing the attack).

In `telnet.pcapng`, you should be looking for the password to the telnet server.

## Submission Format
The tokens you submit will be the IP address of the node performing the indicated network activity. There are four (4) submission parts as follows:

1. The IP address of the node performing a SYN flood attack
2. The IP address of the node performing a port scan
3. The IP address of the node performing a Shrew attack
4. The password for the telnet service (16 character alphanumeric string)


## References  
[1] Haris, S. H. C., R. B. Ahmad, and M. A. H. A. Ghani. \"Detecting TCP SYN flood attack based on anomaly detection.\" 2010 Second International Conference on Network Applications, Protocols and Services. IEEE, 2010.

[2] Gadge, Jayant, and Anish Anand Patil. \"Port scan detection.\" 2008 16th IEEE International Conference on Networks. IEEE, 2008.

[3] Kuzmanovic, Aleksandar, and Edward W. Knightly. \"Low-rate TCP-targeted denial of service attacks: the shrew vs. the mice and elephants.\" Proceedings of the 2003 conference on Applications, technologies, architectures, and protocols for computer communications. 2003.
