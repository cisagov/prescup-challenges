# Throw Me A Bone

It can be *ruff* keeping an environment secure! Make sure users aren't using easily guessed passwords and apply remediations based on the results of a recent vulnerability scan.

**NICE Work Role**

- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify vulnerabilities
- [T1341](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform required reviews

## Background

Shoot! The vulnerability scanner hasn't run for... well, a long time. **There are six servers in the environment.** Review a recent vulnerability report and resolve the vulnerabilities found in your environment. Identify any user accounts in the MERCH Domain that are using weak or commonly used passwords.

## Getting Started

>**Caution!** Do *not* modify the `user` or `scanuser` accounts in any way as they are used for environment access.

First, use the provided **NTDS.dit** and **HKLM/SYSTEM** files (available at `challenge.us/files`) to identify any MERCH Domain user accounts that use weak or commonly used passwords. There are no inactive users in the Active Directory export meaning all users in the export are active.

Next, use the PDF vulnerability report available at `challenge.us/files` to remediate outstanding HIGH and MEDIUM vulnerabilities in the environment. An "in challenge" vulnerability scanner is available at `scanner.merch.codes` for you to verify a system has been remediated.

Once all systems are complete, run the Grading Check at `challenge.us` to receive your token and the answer to Question 2. If your Grading Check fails, remember to use `scanner.merch.codes` to validate that you have all of the necessary remediations in place on each of the six servers.

## Challenge Questions

1. What is the username of the MERCH Domain account which is using a weak and/or commonly used password?
2. What is the 8-digit hexadecimal code you received from the grading check (`challenge.us`) after remediating vulnerabilities on all six servers in the environment?