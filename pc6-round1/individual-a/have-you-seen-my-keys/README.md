# Have You Seen My Keys?

Analyze Windows files to identify user actions and USB key information.

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Digital Evidence Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1324](https://niccs.cisa.gov/workforce-development/nice-framework/): Process digital evidence.
- [T1489](https://niccs.cisa.gov/workforce-development/nice-framework/): Correlate incident data.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

Malware has been executed on one of our systems. Your task is to determine *who* ran the malware and the location from where it was executed.

**RegRipper** and **Forensic Registry EDitor (fred)** have been installed on your system.

Learn more:

- [RegRipper Documentation](https://www.sans.org/blog/regripper-ripping-registries-with-ease/)
- [Fred Documentation](https://www.sits.lu/fred)

## Getting Started

Download the **user**, **registry**, and **prefetch** information from: `challenge.us/files`.

## Challenge Questions

1. Which user ran the file runme.exe?
2. What was the usb drive volume name runme.exe was run from?
3. What is the timestamp from when was this drive first connected?