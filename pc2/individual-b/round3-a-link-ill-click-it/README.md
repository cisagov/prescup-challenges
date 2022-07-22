# A link? I'll click it!

You must use existing email infrastructure to gain access to a user's machine.

**NICE Work Role:** 

- [Exploitation Analyst]https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation%20Analyst&id=All&fwid=All&name_selective=Exploitation%20Analyst)

**NICE Tasks:**
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0028&description=All) - Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0028&description=All) - Perform analysis for target infrastructure exploitation activities."

## IMPORTANT

There are no downloadable artifacts provided for the challenge. The full challenge can be completed on the hosted site.

## Background
You are tasked to perform a phishing assessment on the MakeStuff Company.  Your assessment should show that you can use email to compromise a user machine which leads to escalation of privileges.

Based on your intel gathering, you determine that Austin, a user at the MakeStuff Company, is expecting an email from Kaye, a coworker. Kaye is leading an internal development project and is expected to send a download URL for the program.

Because of urgent tasking, Austin will follow the link from Kaye, then download and execute the program.

## Getting Started

You can view the [challenge guide](challenge-guide.pdf) here.

Your task is to send a plain text email to apost@makestuff.company from kbrady@makestuff.company. This email can include any URL (must begin with `http://`). A GET request to the URL should result in a program being downloaded. The program will be executed on the user's machine. 

Use this initial vector to gain access to Austin's machine and then escalate your privileges. 

There is a log hosted on Austin's machine that will show the status of Austin's emails and processes. 

## Submission Format
There are 2 submission parts to this challenge. Both tokens are in text files at the root of the target file system. The tokens will be 16 character strings.

The first token will be readable by any user on the file system. The second token will only be readable by a user with elevated privilege.

