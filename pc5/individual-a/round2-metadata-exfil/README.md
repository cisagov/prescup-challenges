# Meta Data Exfil

Investigate recovered files to gain access to a data storage site where additional information can be exfiltrated from those files.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework/): Examine recovered data for information of relevance to the issue at hand.
- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation) tasks to support deployable Incident Response Teams (IRTs).


## Background

Our allies, the Galorians, are under attack, rendering all of their tech administrators unreachable. They rely on the data within their data storage site to defend themselves; however, they have been unable to gain access to this site. Help the Galorians obtain access before it is too late.

Numerous publicly available PDF files from the Galorian space station have recently been recovered. These files hold credentials to log into the Galorian data storage site where we will help find the information they need to defend against their assailants.

## Getting Started

Retrieve the recovered files from `challenge.us`. There is a Galorian data storage site on the `10.2.2.0/24` network that contains additional files, though it requires proper credentials.

Use the recovered files to find the credentials to the Galorian data storage site. Access the data storage site, parse through the stored files, and recover information critical to Galorian defense.

There are two additional tools, **pdfimages** and **xxd**, that have been added to the Kali machine.

## Challenge Questions

1. What is the token found after logging into the website on the network?
2. What is the token located inside of mysterious_object_found.docx?
3. What is the token located in delidian.zip?
