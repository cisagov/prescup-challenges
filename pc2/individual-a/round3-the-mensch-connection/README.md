
# The Mensch Connection

You will follow a set of network traffic related breadcrumbs in order to find the external system responsible for exfiltrating a set of data, and then connect to this system to discover what data was stolen.


**NICE Work Role:**

  - [Cyber Defense Incident Response](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Incident+Responder&id=All)
  - [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst&id=All)

**NICE Tasks:**

  - [T0161](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0161&description=All)- Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
  - [T0166](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0166&description=All) - Perform event correlation using information gathered from a variety of sources within the enterprise to gain situational awareness and determine the effectiveness of an observed attack.
  - [T0258](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0166&description=All) - Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.

## IMPORTANT
This challenge is only partially open sourced. The files listed below can be downloaded and are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc2/individual-a-round3-the-mensch-connection-largefiles.zip)
and extract in _this directory_ to get started.

Use your preferred platform and tools to analyze the included files.

## Background

You are responding to an insider threat incident within the ACK-ME network. It is believed that two employees colluded to steal corporate data, though the methods are not fully known at this time. Since the insiders used allowable methods for pulling this off, there are no IDS or security events to go off of. You have only an overall packet capture from the time frame where the events took place, an export of the firewall states table around the time of the incident, and the current state of the network at your disposal. This data can be found in the downloaded zip file.

The objective of this challenge is to follow a set of breadcrumbs, by means of analyzing various network traffic events, in order to retrieve the final token within the stolen data. Questions about the data you are seeing will be asked along the way to ensure that you can receive partial credit and are on the right track. The answer to each question will help you find the next breadcrumb and the questions themselves can be used as hints on what to look for.

The first breadcrumb to be found is related to chat channel traffic between users within the network. It is believed that the insiders coordinated via their own internal chat server in the MGMT network, which has since been removed by them. You must investigate the packet capture provided and use network resources to find the chat between the insiders. This will lead you to your next clue.

Please see the included [challenge guide](challenge-guide.pdf) for additional information.

## Winning Conditions

In order to receive full credit for this challenge all four tokens must be retrieved which require following the trail of network activity to its conclusion and answering four question about the activities that you see.

## Submission Format

The submissions for this challenge will consist of alphanumeric strings and IP addresses. Alphanumeric strings will not include any punctuation or spaces. The lowercase l and the number 1 have been removed to eliminate any confusion between the two.
