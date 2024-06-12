# Git to It

Your team discovers an enemy Gitlab instance with sensitive information. Use your exploitation skills to obtain the flag. 

**NICE Work Role**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/): Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0572](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply cyber collection, environment preparation and engagement expertise to enable new exploitation and/or continued collection operations, or in support of customer requirements.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

While gathering intelligence on an enemy ship, your team discovers a Gitlab instance. Further investigation shows there's an active user currently making edits to a public project. There seems to be sensitive information saved in this public project that suggests there's a possibility a private project exits as well. You have been tasked to use this to your advantage in an attempt to retrieve information from that private project. 

## Getting Started

Navigate to `https://gitlab.awkward.org` and create an account. Go to the only public project to find the first flag and a runner registration token. Use the discovered runner registration token to find a way to retrieve the "Dev Man" user private project and obtain the second flag.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|Challenger-Kali|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What's the first flag found inside the public repository?
2. Once you obtain access to the information inside the private repository, what's the second flag located inside the README.md file?