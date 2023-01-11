# In and Out, 30-minute Adventure

A group of Xeno cultists obtained the plans for a high-security vault containing ancient Seelax relics. The codes needed to unseal the vault are in the plans. The Xeno cultists have made the vault plans publicly available on a website. Find the machine hosting the website, exploit it, and delete those files!

**NICE Work Role**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)
- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-operator)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0028) - Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0696](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0696) -  Exploit network devices, security devices, and/or terminals or environments using various methods or tools.
- [T0644](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0644) - Detect exploits against targeted networks and hosts and react accordingly.
- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0736) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

Some valuable data that will help your team complete its task(s) has already been gathered.
- `websiteRecords.csv`: contains the records of those who may have an account on the website hosting the files. 
- `credential_parse_method`: contains information on how user accounts are generated for the website. 

Both files can be found on either of the `net1-insider` machines.

Information about the network can be seen below (or in a new tab <a href="https://launchpad.cisa.gov/tm/docs/56da984c210247e79624409869359637/network-1984993485.jpg" target="_blank">here</a>).
![](https://launchpad.cisa.gov/tm/docs/56da984c210247e79624409869359637/network-1984993485.jpg)

Further enumerate the network, exploit the defenses, reach the machine hosting the file, and delete it. <!--is it file or files?-->

## Getting Started

None of the insider VMs have been configured with an IP address. You will need to:

- Logon and configure each of the `insider` systems with a valid IP address based on the network diagram provided.
- Analyze the provided files on the `net1-insider` machines. 
- Use the available tools to gather information about the environment and gain access to the machine hosting the targeted website.

## Challenge Questions

1. Find the SMB Share password.
2. Find the FTP password.
3. Log into the website and find the pin.
4. Browse to `https://200.99.5.5` and begin the grading check. You will be presented with a hex token upon successful completion.

