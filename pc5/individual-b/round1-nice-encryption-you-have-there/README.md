# Nice Encryption You Have There...

In this challenge, you are asked to perform binary analysis and then write code taking advantage of what you learned.

**NICE Work Roles**

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0253](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0324](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze internal operational architecture, tools, and procedures for ways to improve performance.


## Background

Understand how a program is linked to an external library and then loaded as a running process. Write code to intercept a function call so you can add your own code to the call.

## Getting Started

From the Kali system browser, go to `challenge.us/files` and download `client`. Complete your analysis on this binary file.

The token for the second question has a 1/10000 probability of being sent by the server in any given connection attempt. It will be wrapped like this to make it easy to find once you've solved the challenge: `token{abcdef0123456789}`.

***Hint:** The* `LD_PRELOAD` *environment variable will help you with this challenge, but it is not required to solve the challenge.*

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the name of the function being used to decrypt messages from the server?
2. What is the decrypted token?
