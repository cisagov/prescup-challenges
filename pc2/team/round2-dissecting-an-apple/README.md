# Dissecting an Apple

Analyze a forensic image to answer a few questions. 

**NICE Work Role:** 

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0286](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform file system forensic analysis.  
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework) for recovery of potentially relevant information."

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the forensic disk image (the `EVIDENCE` drive) from [here](https://presidentscup.cisa.gov/files/pc2/team-round2-dissecting-an-apple-largefiles.7z) to play this challenge offline. The file is a 7-zip archive that is ~15.5GB zipped and 40GB unzipped. 


## Background

You are provided with a forensic image. Your task is to use the tools available to you to analyze the image and answer the following questions.


## Getting Started

The `EVIDENCE` drive containing the forensic image (`image.dd`) is attached to the Analyst VM.

Your goal is to answer the following questions - 
1. The laptop owner met his friend at a certain type of restaurant. When (in UTC) did they meet?
2. Which restaurant did they meet at?
3. Which city is the laptop owner likely located in? 
4. Which browser was used to download a certain file?
5. Name a specific application used on the laptop.
6. Provide the `NX Block Number` of the APFS container present in the image. 
