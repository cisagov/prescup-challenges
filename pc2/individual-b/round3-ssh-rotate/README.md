# SSH Rotate

Determine an attacker's intentions by deliberately granting them access.

**NICE Work Roles:**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0695](hhttps://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0695&description=All#) - Examine intercept-related metadata and content with an understanding of targeting significance.
- [T0500](https://niccs.cisa.gov/workforce-development/nice-framework) - Modify and maintain existing software to correct errors, to adapt it to new hardware, or to upgrade interfaces and improve performance.

## IMPORTANT

This challenge has no downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

An adversary is conducting a brute-force SSH attack against an asset within your network. It is important to know what is at risk if the attacker manages to breach the network. As luck would have it, the targeted machine happens to be a test system with no sensitive data on it. Take advantage of this opportunity to learn the attacker's intentions by deliberately giving them access.

## Getting Started

You can view the [challenge guide](challenge-guide.pdf) here.

Log in to the _kaliwebtest_ system. Use any means at your disposal to intercept and read the attack traffic, then monitor the actions the attacker takes once he is able to authenticate. The submission token will appear as a file named `submission.txt` located in the home directory of the compromised user account.

## Token Format

The token for this challenge is an 8-byte value represented by 16 hexadecimal digits. All letters will be lower case.
