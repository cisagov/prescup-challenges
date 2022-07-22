# In One Ear and Out the Other

This challenge is aimed at testing your ability to analyze memory artifacts and correlate those findings with network packet captures to answer questions regarding a recent network compromise.

**NICE Work Role:**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All#)  
- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Network+Operations+Specialist&id=All)

**NICE Tasks:**

- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0027&description=All) - Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.  
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0240&description=All) - Capture and analyze network traffic associated with malicious activities using network monitoring tools.  
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://cisaprescup.blob.core.usgovcloudapi.net/pc2/team-round2-in-one-ear-largefiles.zip)
and extract in _this directory_ to get started.

## Background

You and your team are consultants that provide forensic analysis services. You have been called in from a customer organization that had recently encountered a network breach and data leak. You will not have access to live systems, only memory images and network traces that have been collected by initial incident response teams. However, you find that the memory artifacts were collected from only a server on the network and the packet capture had only been collected from the network's firewall.

Reports from the incident response team indicated that the attacker had used a couple of methods to try and mask movements both on the network and locally on the compromised server. The attacker was also able to evade data loss prevention systems by using unconventional protocols, alternate transmission timing, and data obfuscation techniques.

Furthermore, the server administrator indicated that the server had contained several sensitive files including files with financial information for both employees and customers, a file with usernames and passwords and a file with contact information. The server administrator admitted that these findings had been reported in a recent vulnerability assessment, but were not taken into consideration since the server was protected by a firewall.

## Getting Started

Based on the artifacts, you will be asked a series of questions that will prompt you to investigate various parts of each and in some cases correlate information between them.

Using tools like Volatility and Wireshark will help you answer the questions provided below.

## Questions

1. What IP address did the attacker send data to?

2. What is the name of the file that was exfiltrated from the victim machine?

3.  Following the initial transaction, what was the chunk size of packet data (in bytes) that was being exfiltrated by the attacker malware?

4. What port is the attacker using to pivot into the victim machine?

5. What is the first listed physical offset of the initial exploit?
