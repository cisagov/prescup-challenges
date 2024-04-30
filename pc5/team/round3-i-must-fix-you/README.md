# I Must Fix You

Perform binary analysis on corrupt files to repair them and recover the data within.

**NICE Work Roles**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0077](https://niccs.cisa.gov/workforce-development/nice-framework): Develop secure code and error handling.
- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework): Examine recovered data for information of relevance to the issue at hand.
- [T0167](https://niccs.cisa.gov/workforce-development/nice-framework): Perform file signature analysis.
- [T0253](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct cursory binary analysis.


## Background

An organization is recovering after a cyber attack and has hired you to recover data within several files corrupted during the attack.

The corrupted files and filetypes are:

- one (1) PDF
- one (1) ZIP
- one (1) PCAP
- eight (8) image files, filetype unknown

The organization has information on some of these files and has provided it via the `instructions.txt` available on `https://challenge.us`. The information provided should help with the data recovery. 

## Getting Started

Log into the Kali VM and browse to: `https://challenge.us/files`. Download `instructions.txt` and `corrupted_files.zip`.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the 8-character hex string found in the PDF after successfully repairing it?
2. What is the 8-character hex string found in the ZIP after successfully repairing it?
3. What is the 8-character hex string created by concatenating the contents of each image after successfully reassembling them?
4. What is the 8-character hex string found in an image in the packet capture (PCAP) after successfully repairing and extracting it?
