# Jailbreak

Ensure that there are no major security flaws in the *Dauntless*' systems by analyzing one of its servers for vulnerabilities. 

**NICE Work Roles** 

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.

## Background

Before the *Dauntless* can depart, its systems need to be checked for vulnerabilities. 

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the required files from [here](https://presidentscup.cisa.gov/files/pc4/individualb-round2-jailbreak-largefiles.tar.gz) and follow the instructions in the [challenge directory](./challenge) to configure the server needed for this challenge. The zipped file is ~62MBs and will be imported into `Docker`.

## Getting Started

Inspect an HTTP API server -- intended to eventually handle the _Dauntless_' non-critical personnel management functions -- for vulnerabilities.

- First, download the zipped server source code: [Server source](http://localhost/static/source.zip).
- Next, view an **OpenAPI** schema of the endpoints: [Schema](http://localhost/schema).

Using this information and the file paths provided in the challenge question submission labels, retrieve the challenge flags.

## Submission Format

The offline version of this challenge uses the string `Success!` in place of flags.

## Challenge Questions

1. /app/flag1.txt (in container)
2. /root/flag2.txt (out of container)
