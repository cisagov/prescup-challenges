# The Fast and the APFS

Examine a forensic disk image of an Apple computer.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework/): Decrypt seized data using technical means.
- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework/): Examine recovered data for information of relevance to the issue at hand.
- [T0216](https://niccs.cisa.gov/workforce-development/nice-framework/): Recognize and accurately report forensic artifacts indicative of a particular operating system.
- [T0396](https://niccs.cisa.gov/workforce-development/nice-framework/): Process image with appropriate tools depending on analyst's goals.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the large files [here](https://presidentscup.cisa.gov/files/pc5/individuala-round2-the-fast-and-the-apfs.zip). The disk image extracted from the large file zip was provided to competitors as an ISO during the competition. The zipped file is ~18 GBs and the extracted file is ~45 GBs.

## Background

Examine the Mac OS X image file located on the second drive of the Kali machine and answer five questions related to data retrieved from the device image. 

## Getting Started

On the Kali VM desktop, double-click **54 GB Volume**. The drive mounts at:  `/media/user/02f1a38-a52b-4410-aa1e-5eb9ab08537a/`. This requires root permission, so enter `tartans` at the prompt.

The Kali VM has the Java version of Autopsy installed at:
`/home/user/autopsy/autopsy-4.20.0/`; in this directory, run: `sudo bin/autopsy`.

## Challenge Questions

1. What is the string value of the "LocalHostName" for this machine?
2. An email was drafted but not sent with the subject of "Dinner".  There is an image attached to it.  What is the MD5 hash of the image?
3. What is the md5 hash of the user's desktop background picture?
4. A file named "p1it.pdf" was downloaded from the internet.  What is the full URL of the file? (Include https://)
5. What is the MD5 hash of the user's profile picture?
