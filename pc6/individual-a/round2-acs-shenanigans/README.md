# ACS Shenanigans

Analyze log files for signs of sensitive data exfiltration, monitor network traffic for active breaches, and develop a script to simulate Access Control System(ACS) scan replays.

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics)
 
**NICE Tasks**

- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify anomalous network activity
- [T1102](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify intrusions

## Background

The Security Operations Center (SOC) has detected anomalous broadcasts originating from a device within the internal network. 

## Getting Started

Using the provided Kali machine:

## Part 1

### Description:

 Preliminary investigations suggest an unauthorized network tap has been installed, intercepting and relaying sensitive data to an external relay device.

Analyze the provided log file and parse it according to the attached specification. Your goal is to extract the relayed data and identify any credentials or sensitive information transmitted. Time is critical—help the SOC gain visibility into this incident and prevent further data exfiltration.

`fac_187.log` & `Spec.md` are both hosted at `challenge.us` in your web browser.

### Objective:

- Analyze the provided log file (`fac_187.log`)
- Parse the log using the given specification (`Spec.md`)
- Use the spec documentation to decode the information to answer the challenge questions.

## Part 2

### Description:

Use Wireshark to monitor the network and check if the unauthorized data exfiltration is still occurring. Capture and analyze traffic for signs of the rogue device relaying data, focusing on unusual packets or destinations. Correlate your findings with the previous log analysis to confirm if the breach is ongoing.

### Objective:

- Run Wireshark.
- Analyze access control scans that are broadcasted.
- Use the provided spec to decode the network traffic.

## Part 3

### Description:

Create a script to replay a provided Wiegand frame and determine which door becomes unlocked. Your task is to simulate the replay to trigger the door controller. The IP address for the controller will be discovered via packet capture in Part 2.

Note: Consider using tools that can easily send raw data over a network connection to interact with the controller.

### Objective:

- Write a script to replay this scan data:
    - `01011101100000101001110011`

- Determine which door becomes unlocked.
    - A valid replay will prompt the controller to respond with the name of the door it controls.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|acs-kali|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.