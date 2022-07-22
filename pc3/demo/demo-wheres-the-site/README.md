
# Where's the site?  

There was an update to a mission critical website, but we don't know where the new site is. Can you help?

  **NICE Work Roles:**   

  [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)


  **NICE Tasks:**

  - [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0266&description=All) - Perform analysis for target infrastructure exploitation activities.

## Setup

Move the files in the challenge folder into your virtual machine. Once the files are in the virtual machine, run the startup.sh file then you'll be able to begin the challenge.

```bash
./startup.sh
```
 
## Background

An update to the mission-critical website `http://your_local_machines_IP_address` has changed which port the website is hosted on. You must scan the host to determine which port the website is hosted on and collect the token from the hosted file. 

## Getting Started

Open your local machine and perform a port scan of `http://your_local_machines_IP_address` to find which port is hosting the website. Then download the `tokenfile`. 

## Submission Format

There are two (2) submissions for this challenge. For the first submission, enter the port number which is hosting the website. The second submission token will be a 32 character string found inside of the `tokenfile` on the website. 

1. What is the challenge.us port number?

2. What is the hex value of the tokenfile?
