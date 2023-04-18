
# Pre-launch Training

Welcome prospective crew members! Before you are allowed to board the Dauntless, humanity's first faster-than-light capable ship, we must ensure that you are familiar with using all the mission critical systems on board. This simulation will allow you to experience a representative crisis situation, just like you might encounter in-orbit.
<br><br>
The challenges you might face in space are sure to be significantly more complex, but the steps to ensure that the ship's systems register your actions will be the same. Good luck!


  **NICE Work Roles**

  - [Cyber Defense Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)


  **NICE Tasks**

  - [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.


## Background

In this simulation, one of the systems onboard the ship has been damaged by a solar flare. You were able to recover an image from the malfunctioning thumb drive that was plugged into the system, as well as a secured backup file. The password to this file used to be on the thumb drive, but it looks like someone recently deleted it. You must use whatever means at your disposal to gain access to the activation code for this system.


## ⚠️ Large Files ⚠️

This challenge includes large files as a separate download. Please download the files [here](https://presidentscup.cisa.gov/files/pc4/demo-pre-launch-training-largefiles.zip) and extract the `image.img` file before beginning. The zipped file is ~4GBs and the extracted artifact is ~9.5GBs. 
 

## Getting Started

Begin by mounting the image file `image.img`. You must analyze the contents to find the first token.


## Submission

There are three (3) submissions for this challenge. Each token is a 16 character hexadecimal string.

1. What is the token found within the image file?

2. What is the token found within the zip file?

3. What is the token found on `https://challenge.us`?  (When playing this challenge offline, you can receive this token by running `python3 gradingScript.py <the activation code you find>` where the activation code for this challenge is an argument to the grading script)


