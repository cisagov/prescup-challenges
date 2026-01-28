# Off the Hook

Find and remove two worms that have infected the system, and mitigate the vulnerabilities that allowed them to gain a foothold on the system.

**NICE Work Roles**

- [Incident Response](https://niccs.cisa.gov/tools/nice-framework)
- [Defensive Cybersecurity](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities
- [T1119](https://niccs.cisa.gov/tools/nice-framework): Recommend vulnerability remediation strategies
- [T1389](https://niccs.cisa.gov/tools/nice-framework): Remove malware

## Background

You're going undercover as a security engineer to gain access to confidential information being held by a software development agency. However, they've become a bit suspicious of your willingness to take such a job given your qualifications. Before they grant you wider access, they've tasked you to prove your skills are real by resolving a breach on one of their smaller networks. 

They believe the system has been infected by two worms. Fix the vulnerabilities, remove any artifacts related to the worms, and get yourself... "Off the Hook".


## Getting Started

Use your Kali host to get started and investigate the other hosts on the network. The hosts that are believed to be infected are `internalreports.pccc` and `publicsite.pccc`.

Note that the `attacker.pccc` host represents the entire internet, not a single literal adversary. All of the other hosts on the network must be able to interact with the sites normally for grading to succeed (that is, you cannot simply block all access).

**The worms and any other related artifacts should be removed entirely, not simply disabled.** Moving the artifacts to the home directory, your Kali host, or another location is also acceptable.

## Tokens

The tokens are formatted as `PCCC{some_words123_here}`.

Tokens 2, 3, 5, and 6 require a grading check, which is performed by visiting `http://challenge.pccc`. 

1. Find the token hidden as a comment in the worm script on `internalreports.pccc`
2. Remediate the vulnerability that allowed the worm to gain access to `internalreports.pccc`
3. Remove all artifacts related to the worm on `internalreports.pccc` (there are two)
4. Find the token hidden as a comment in the worm script on `publicsite.pccc`
5. Remediate the vulnerability that allowed the worm to gain access to `publicsite.pccc`
6. Remove all artifacts related to the worm on `publicsite.pccc` (there are two)

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-VNC|user|password|
|internalreports.pccc|user|password|
|publicsite.pccc|user|password|

## Note

Attacking or unauthorized access to `challenge.pccc` is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
