# Color Theory

Here you are given a Mac (not a PC). Analyze the acquired memory dump and answer the following questions.

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics)

**NICE Tasks**

- [T1301](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics): Report forensic artifacts indicative of a particular operating system
- [T1486](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics): Process forensic images
- [T1607](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/digital-forensics): Recover information from forensic data sources

## Background

There are limited tools for MacOS in the field of digital forensics and even fewer open source solutions. In this challenge, you will need to leverage Volatility 3, the current version of the memory forensics framework.

## Getting Started

Log in to the ``analyzer`` VM and download the memory artifacts from ``challenge.us``. The ``analyzer`` system is a Kali Linux VM with ``volatility3`` and ``dwarf2json`` pre-installed. 

In support of a more modular framework, Volatility 3 introduces a system that relies on symbol tables, specifically Intermediate Symbol Format (ISF) files, to interpret the macOS kernel and other system structures. 

Utilize the files located in ``/home/user/challenge_files/`` to assist in examining the memory dump files downloaded from ``challenge.us``.
 
## System and Tool Credentials

| system/tool | username | password |
| ----------- | -------- | -------- |
| analyzer    | user     | tartans  |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the Darwin Kernel Version of the compromised host?
2. What is the name of the exfiltrated file from the compromised host?
3. What is the virtual memory address of the shell code executed on the compromised host?