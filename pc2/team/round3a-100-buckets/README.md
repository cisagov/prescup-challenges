# 100 Buckets

This challenge is aimed at testing your ability to analyze three separate workstations that have been infected with ransomware. 

**NICE Work Role:**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All#)  
- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Network+Operations+Specialist&id=All)

**NICE Tasks:**

- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0027&description=All) - Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.  
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0240&description=All) - Capture and analyze network traffic associated with malicious activities using network monitoring tools.  
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information

## IMPORTANT

There are no downloadable artifacts for this challenge. The challenge can be completed on the hosted site.

## Background
	
You have identified three separate workstations on your network that have been infected with ransomware. The ransomware is steadily encrypting files in each local workstation's shared drive, and backups on the server have also been compromised. 

You are tasked with finding the decryption keys that are stored in a separate location on each machine, with each key being specific for the infected files on that workstation's shared drive. You must locate the key on each machine BEFORE all files have been encrypted and the program ends. 


## Getting Started
To start, your team has access to all three Windows 10 workstations. There is a \"BucketReadMe\" text file and a \"decrypt-file\" PowerShell script saved on the desktop for you to review. This provides to specific instructions on how to decrypt the files once you locate the keys. The keys are stored in plaintext and in some cases you must change them from hex to base64 to decrypt the files.

The keys are stored in a separate location for each machine:

- Derk: Registry

- Lydia: Network traffic

- Axel: RAM

To obtain each answer you must decrypt the first file in the group share folder to find the flag for each machine. The file name for each group share is:

- Derk: Group A --> aaaron --> aaa_master.txt

- Lydia: Group B --> ganders --> aaa_master.txt

- Axel: Group C -->  nnitto --> aaa_master.txt

There is a \"tools\" folder on each of the machine desktops with a variety of forensic tools for you to use. You may also leverage system tools as needed to solve the challenge. 

## Completion Note
In order to complete the challenge you will need to leave the malicious program running on each machine. DO NOT CLOSE the program running on each machine. If you do close the program, you may restart it at any time or reboot the computer.
