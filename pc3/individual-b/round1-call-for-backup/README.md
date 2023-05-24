 # Call for Backup

Your Linux Administrator has developed a new backup process and would like you to confirm it is secure.  You've been appointed the task of reviewing the new "Infrastructure-as-Code" backup script  the Linux Administrator has created. There are two hosts in the infrastructure (web and db) currently using this script. 

**NICE Work Role:**

[Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks:**
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct and/or support authorized penetration testing on enterprise network assets.

- [T0252](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct required reviews as appropriate within environment.

## IMPORTANT

This challenge requires a hosted environment to fully solve as it was intended.  
The files provided in the [challenge folder](challenge) are provided as part of open sourcing. Use these files as a starting point if you want to build your own version of this challenge.

## Getting Started
Your job is you see if you can leverage the backup script to gain root access and retrieve the token located in /root:

- All scripts used for the backup process are located in /usr/local/bin
- The user account has sudo access
- SSH access is already setup for the 'user' account to authenticate to all hosts without a password

To execute the script you need to call its name and provide an action, ex:

`backup.py backup`

## Submission Format
Scoring for this challenge will consist of 2 tokens located in /root/token.txt of web and db.
