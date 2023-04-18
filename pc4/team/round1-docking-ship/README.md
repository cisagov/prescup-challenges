# Docking Ship

Analyze a forensic image to investigate a service outage. 

**NICE Work Roles** 

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-forensics-analyst)

**NICE Tasks**

- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0532) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download [here](https://presidentscup.cisa.gov/files/pc4/team-round1-docking-ship-largefiles.zip) to get started. The zipped file is ~5GBs and the extracted artifact is ~15GBs.

## Background

Mars relay satellites (spacecrafts and antennas) are not able to communicate with each other. There is a suspicion that the Deep Space Network might have been a victim of a cyber attack. We have forensically acquired a system from the Deep Space Network that runs their web stack. You're provided with that forensic image. Your goal is to analyze that forensic image to determine what might have happened. 

## Getting Started

The iso containing the forensic image (`image.raw.zip`) is attached to the Analyst VM. Please unzip the file, and then use the tools available on the Analyst VM to analyze the image and answer the questions.

## Challenge Questions

1. What are the first eight characters of the container ID of flask container?
2. What is the name of nginx container?
3. What is the name of the database that the flask app connects to?
4. What is the name of the table that was deleted through SQL injection?
5. How many records were present in the deleted table?
6. What is the user agent string of the web request that resulted in deletion of the table?
