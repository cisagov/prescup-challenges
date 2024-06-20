# Connect the Dots

Find and exploit a vulnerable web server to obtain root access. 

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/): Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0572](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply cyber collection, environment preparation and engagement expertise to enable new exploitation and/or continued collection operations, or in support of customer requirements.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

A web server is hosted on the `10.5.5.0/24` network. Find out the IP of the web server and look for vulnerabilities that allow you to obtain a shell into the system. From here, look for ways to perform privilege escalation and obtain root access. 


## Getting Started

Start with an Nmap scan to discover what IP address and port the web server is running on.

## Challenge Questions

1. After obtaining a shell inside the web server, the first flag will be found under `/opt/tomcat/flag1.txt`.
2. Find a way to log into the `ansible` user. Second flag will be under `/home/ansible/flag2.txt`.
3. Perform privilege escalation to get root access on the web server box. Third flag will be under `/root/flag3.txt`.