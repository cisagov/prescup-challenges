# World Wide Whoops


Challengers must read code for websites to find potential security vulnerabilities. Challengers will  exploit 4 different web vulnerabilities to complete the challenge.

**NICE Work Roles:**   

- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Vulnerability+Assessment+Analyst&id=All)

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Software+Developer&id=All)   

**NICE Tasks:** 

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0028&description=All) - Collaborates to identify access and collection gaps that can be satisfied through cyber collection and/or preparation activities. Leverages all authorized resources and analytic techniques to penetrate targeted networks.  

- [T0176](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0176&description=All) - Perform secure programming and identify potential flaws in codes to mitigate vulnerabilities.


## IMPORTANT

This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.


## Background

There are four vulnerable websites at IP address 192.168.1.10 on ports 5001, 5002, 5003, and 5004.   The code for each website is provided on the Kali workstations. The provided code may be partially redacted.  

## Getting Started
Visit each website from inside the gamespace and attack it to receive the token.  

__You must visit and attack the website from inside the game environment.__  

1. `http://192.168.1.10:5001  `
2. `http://192.168.1.10:5002  `
3. `http://192.168.1.10:5003 `
4. `http://192.168.1.10:5004  `

Note: Several Python3 libraries are installed on the system (e.g. Requests) that may be helpful in solving this challenge. 

## Submission Format

There are 4 parts to the submission - 1 part for each vulnerable website.   The submission for each part will be a 16 character alphanumeric string.  See the list below for specific instructions for each website's submission. 

**Part 1 of 4:**  
`http://192.168.1.10:5001` - The token will be displayed on the webpage when the required condition is met.

**Part 2 of 4:**  
`http://192.168.1.10:5002` - The token will be displayed on the webpage upon successful exploit of the vulnerability.

**Part 3 of 4:**  
`http://192.168.1.10:5003` - The token file will be downloaded from the server upon successful exploit of the vulnerability.

**Part 4 of 4:**  
`http://192.168.1.10:5004` - The token to submit is the password for the user `admin`.

