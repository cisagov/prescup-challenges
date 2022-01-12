# Treasure Hunt

Analyze forensic images for hidden data. 

**NICE Work Role:** 

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

**NICE Tasks:**

- [T0286](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0286&description=All) - Perform file system forensic analysis.  
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://cisaprescup.blob.core.usgovcloudapi.net/pc2/team-round3a-treasure-hunt-largefiles.zip)
and extract in _this directory_ to get started.

## Background
You are provided with forensic images of a USB drive and a laptop acquired from a suspect's home. The suspect is known for hiding data in file slack and NTFS Alternate Data Streams.  Your task is to analyze the images and find the hidden data.

## Getting Started

There are two external drives attached to all the Analyst VMs. The drives are yet to be mounted on `Analyst-SIFT` VM.
* The `EVIDENCE` drive (~50GB) contains the forensic images (`laptopimage.dd` and `usbimage.dd` ). At the time of acquisition, both laptop and USB were APFS formatted.
* The `EXTRA-STORAGE` drive (~60GB) is just an empty drive in case you run out of space on the local disk.

Your goal is to perform the following tasks to find hidden data in both images - 
1. Analyze the file slack (last 2-4 bytes) for image files (png/jpeg)  present in the `Downloads` folder of the laptop image. The answer string is formed by concatenating the data found in the file slack when the files are arranged in ASCII order of their names.

2. Analyze the NTFS Alternate Data Streams of files and folders. The answer string is formed by concatenating the data found in the alternate data streams when the files and folders are arranged in ASCII order of their names. (Ignore the absolute path for files and folders. Just sort them based on their names).

Please Note - 
* Answer strings only contain printable ASCII characters but do not contain the space character (`0x20`) 
