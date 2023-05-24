# Look at me, I'm the Captain Now
  
A radical isolationist group opposed to Earth's involvement in galactic affairs have infiltrated the ship's network and sabotaged multiple services and files by reconfiguring them with new credentials. Your teams job is to analyze the documents found, determine the methods used and re-gain access to these services.

**NICE Work Roles**   

- [Data Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0278](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.
- [T0383](https://niccs.cisa.gov/workforce-development/nice-framework) - Program custom algorithms.
- [T0403](https://niccs.cisa.gov/workforce-development/nice-framework).
- [T0404](https://niccs.cisa.gov/workforce-development/nice-framework) - Utilize different programming languages to write code, open files, read files, and write output to different files.

## IMPORTANT

This challenge is only partially open sourced. The files in the [challenge directory](./challenge/) directory are provided to give you a starting point if you wish to recreate the challenge on your own. After following the setup instructions in the [challenge directory](./challenge/), Question 1 can be answered offline using the files provided/generated. 

## Background  

As the Dauntless' drive spins up and you enter cube-space, you attempt to log onto one of the services on your ship. You soon realize that none of the previous credentials are working. You check the construction crew's journal -  it seems they they were already aware of the issue and had intended to remedy it "soon". 

According to their notes, there is a file, and multiple services aboard the ship that have been altered and no longer allow access with any of the previously configured credentials. The construction crew's initial investigation uncovered a handful of documents that were not fully deleted. Thanks to their efforts these documents recovered. One of the documents contains the instructions used by the saboteurs, and although they were unable to determine who did it, they expected to be able to reverse the damage done by following their footsteps.

The main document elaborates on the targets of the attack, they were: `FTP`, `SMB`, an internal `website`, the admin `TCP Server`, as well as a `zip` archive containing multiple critical files which are encrypted with a password. They hoped that by denying access rather than breaking/destroying these targets that they would have collateral to utilize in the event of their capture. This document goes on to describe the methods used, incorporating data from within the accompanying documents to create new credentials for each target which would then allow them exclusive access. 

Your team will have to determine the new authorized credentials being used. You must analyze the recovered documents in order to extract all possible credentials, then utilize this dictionary to attempt all possible options, to find those which allow access. More information and the supporting documents can be found on the challenge server's website. 

## Getting Started

Begin by visiting `https://challenge.us` inside of the challenge environment to download all required files. Analyze these documents and begin working on extracting the various credentials.

## Challenge Questions

There are five (5) parts to this challenge, one for each service/file mentioned above. Each part contains one token which will be presented once you are able to gain access. Each token consists of a 8 character hex string that must be submitted for points.

1. What is the 8-digit hex string extracted from the zip file?
2. What is the 8-digit hex string from accessing the TCP server?
3. What is the 8-digit hex string from accessing the website?
4. What is the 8-digit hex string from accessing the SMB share?
5. What is the 8-digit hex string from accessing the FTP server?
