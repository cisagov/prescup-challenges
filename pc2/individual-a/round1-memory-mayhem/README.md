# Memory Mayhem

You must investigate a memory capture from a victim's machine to answer questions that support a cyber investigation.


**NICE Work Role:**

- [Cyber Defense Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)


**NICE Tasks:**

- [T0238](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0238&description=All) - Extract data using data carving techniques (e.g., Forensic Tool Kit [FTK], Foremost).

- [T0397](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0397&description=All) - Perform Windows registry analysis.

- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.


## Background

You received a memory image from a victim machine that has initially been exploited using [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144). You must determine information about the offending process(es) involved in the attack.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://cisaprescup.blob.core.usgovcloudapi.net/pc2/individual-a-round1-memory-mayhem-largefiles.zip)
and extract in _this directory_ to get started.

Use your preferred forensic tools to analyze the included disk image to answer the questions.

## Getting Started

The image file is mounted to the DVD drive of each gamespace virtual machine. You may use all available forensic tools in either virtual machine to answer five (5) questions for the challenge.


## Questions

1. What is the name of the malicious configuration file that invoked an RDP process?

2. What is the IP address and port where the RDP exploit originated?

3. What is the LastWrite time in hours, minutes, and seconds of the USB thumb drive that was attached to the victim's computer?

4. What is the first PID associated with the marketing.doc file found on the victim's machine?

5. What is the first listed allocation address for the initial exploit that gained access to the victim's machine?


## Submission Format

Enter each answer in the correct submission box.
