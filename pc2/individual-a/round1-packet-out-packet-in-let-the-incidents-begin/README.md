# Packet Out, Packet In, Let the Incidents Begin

You must investigate a set of incidents on your network using a packet capture.

**NICE Work Role:** 
- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**
- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework) - Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0258](https://niccs.cisa.gov/workforce-development/nice-framework) - Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.
- [T0295](https://niccs.cisa.gov/workforce-development/nice-framework) alerts against network traffic using packet analysis tools.
- [T0299](https://niccs.cisa.gov/workforce-development/nice-framework) fingerprinting activities.


## Background

Your network (10.9.8.0/24) has been attacked. You are provided access to a full packet capture file. It is unknown whether the IDS rules included have been tuned and/or baselined, and therefore, some alerts may be benign.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc2/individual-a-round1-packet-out-packet-in-largefiles.zip)
and extract in _this directory_ to get started.

## Questions

1. Some files were transferred in this capture. Which system (IP address) received a file that might be used to perform further network reconnaissance?

2. Which system (IP address) receives the largest amount of data, in bytes, within this packet capture?

3. Which system initiated a port scan within the network (IP address)?

4. How many ports were found to be open/responsive on the scan target host, and what is the value of the highest open port (numerical answers with a single space in between)?

5. What is the 8-character text string found within the shell script contained within the `badstuff.zip` file that was transferred in this packet capture? 

## Hints

Wireshark filters and statistics will be very useful in this challenge. Not every alert is a legitimate incident and not every alert may be relevant. You may safely ignore all OSSEC alerts.
