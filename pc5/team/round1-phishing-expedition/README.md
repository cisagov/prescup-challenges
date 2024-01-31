# Phishing Expedition

Examine forensic artifacts and exploit a web server.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0432](https://niccs.cisa.gov/workforce-development/nice-framework/): Collect and analyze intrusion artifacts (e.g., source code, malware, and system configuration) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework/): Capture and analyze network traffic associated with malicious activities using network monitoring tools.
- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform penetration testing as required for new or updated applications.
- [T0171](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform integrated quality assurance testing for security functionality and resiliency attack.

## Background

One of our employees fell prey to a phishing email! Examine the provided disk image and pcap file then delete the exfiltrated files.

## Getting Started

You've been given a disk image of a Linux workstation and a pcap file of traffic captured after the initial compromise was reported. These files are provided in an ISO attached to each `kali-analyst` workstation. Examine the artifacts to find the source of the compromise and information about exfiltrated documents. Find the malicious website, exploit it, and remove all exfiltrated files.

**\*\*\* Caution! \*\*\***  
This challenge relies on SSH to grade the final task. Do not break or shut down the server hosting the exfiltrated files in any way that would prevent SSH access to it for grading. If the challenge cannot be graded because SSH access to the server has been disabled and you are unable to restore SSH access, you can redeploy the challenge to reset the environment. **WARNING: all progress inside the challenge environment will be lost if you redeploy the challenge**.

## Submission

There are four questions to answer about the breach and one token to retrieve after completing the final task of deleting the exfiltrated files. All tokens are eight character hexadecimal strings. To attempt grading Question 5, visit `https://challenge.us` inside the challenge environment. 

## Challenge Questions

1. What is the campaign id in the link for downloading the avcleaner software that was received via email on 04/19/2023? Note: the file name is in the link

2. According to the logs, what time was the avcleaner malware first executed?  (Answer is in MM/DD/YYYY H:MM:SS XM format eg: 01/01/1970 00:00:00)

3. What is the TCP stream number for transmitting sphericalpedestal.pdf from the user's machine to a remote server?

4. Browse to the remote server that the files were exfiltrated to.  How many .pdf files are on the remote malware target server?

5. Enter the token that is provided by `challenge.us` once the files are deleted from the remote server.