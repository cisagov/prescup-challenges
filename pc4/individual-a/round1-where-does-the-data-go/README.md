# Where Does the Data Go?

Analyze packet captures and live network traffic to investigate a data exfiltration incident.

**NICE Work Roles**

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework) to identify possible threats to network security.

- [T0163](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.

## ⚠️ Large Files ⚠️

This challenge includes large files as a separate download. Please download the large files [here](https://presidentscup.cisa.gov/files/pc4/individuala-round1-where-does-the-data-go-largefiles.zip). The packet capture file extracted from the large file zip was provided to competitors as an ISO during the competition. The zipped file is ~136MBs and the extracted pcap is ~144MBs.


## Background

A user workstation on the _Dauntless_ is suspected of being compromised and appears to be transmitting personnel data to one or more external locations. We provided a packet capture, now we need you to examine the artifacts of this data exfiltration incident.

## Getting Started

_Note: Follow the setup instructions in the [challenge directory](./challenge/) to get started solving this challenge offline._

We provided a packet capture as an ISO and placed it on the Kali Linux machine. You can use this to answer the first five questions. For the last two questions you will need to examine the Ubuntu desktop machine to identify which process is calling home, what data is being sent and where it is going.

## Challenge Questions

1. Something appears to have been exfiltrating user data records from a source on the 10.5.5.0/24 network address space. Using the provided packet capture, identify the IP address where the data is being sent to.
2. Using the provided packet capture, what is the email address of the toxicologist whose data was being exfiltrated in question #1?
3. Using the provided packet capture, what is the password that was sent to a web-based form?
4. Using the provided packet capture, provide the TCP sequence number (raw) of the first packet in the TCP stream for the login attempt in question #3.
5. Using the provided packet capture, what token value was displayed in the image requested from a web server running at 10.5.5.20?
6. Analyze the Ubuntu desktop machine. What are the 8 ASCII characters sent as packet data every 30 seconds?
7. Analyze the Ubuntu desktop machine. What is the name of the script that is actively beaconing to an unidentified target roughly every 30 seconds?
