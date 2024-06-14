# Wait, Don't Open That!

Analyze a collection of suspicious files to uncover their secrets.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework/): Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0260](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze identified malicious activity to determine weaknesses exploited, exploitation methods, effects on system and information.
- [T0296](https://niccs.cisa.gov/workforce-development/nice-framework/): Isolate and remove malware.
- [T0176](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform secure programming and identify potential flaws in codes to mitigate vulnerabilities. 


## Background

Use the provided Kali machines to analyze a collection of documents retrieved from a known threat actor's web server.

## Getting Started

Login to the `kali` VM and open the `Documents` folder. Analyze the documents and search for malicious payloads and evidence of hidden information.

Submit two tokens to complete this challenge. 

1. For the first token discover **Part 1**, **Part 2**, and **Part 3**, then append those strings in order without spaces or delimiters. **Parts 1, 2 and 3** will each be four character strings. For example: if the answer to **Part 1** is `abcd`, and the answer to **Part 2** is `1234`, and the answer to **Part 3** is `grok`, the first token you need to submit `abcd1234grok`.

2. For the second token, discover **Part 4** and **Part 5**, then append those strings in order without spaces or delimiters. **Part 4** is a six character string and **Part 5** is a twelve character string. For example: if the answer to **Part 4** is `456789`, and the answer to **Part 5** is `ABC123DEF456`, then the second token you need to submit would be `456789ABC123DEF456`.

From the Kali VM, navigate to `https://challenge.us` to enter the token values and grade the challenge.

To find the string values associated with Parts 1 - 5, start by analyzing the files in the `Documents` folder of the Kali VM. Look at a combination of documents, scripts and executables. Locate, isolate, and execute potentially malicious code to see how it interacts with a host machine and see the kind of network calls made. 

## Challenge Questions

1. Provide the value for token 1.
2. Provide the value for token 2.
