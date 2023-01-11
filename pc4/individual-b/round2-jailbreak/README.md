# Jailbreak

Ensure that there are no major security flaws in the *Dauntless*' systems by analyzing one of its servers for vulnerabilities. 

**NICE Work Roles** 

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)

**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0266) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0591) - Perform analysis for target infrastructure exploitation activities.

## Background

Before the *Dauntless* can depart, its systems need to be checked for vulnerabilities. 

## Getting Started

Inspect an HTTP API server -- intended to eventually handle the _Dauntless_' non-critical personnel management functions -- for vulnerabilities.

- First, download the zipped server source code: `http://10.5.5.10/static/source.zip`.
- Next, view an **OpenAPI** schema of the endpoints: `http://10.5.5.10/schema`.

Using this information and the file paths provided in the challenge question submission labels, retrieve the challenge flags.

## Submission Format

There are two submissions for this challenge. Each submission is a 16-character lowercase hex string in the format of `0123456789abcdef`.

## Challenge Questions

1. /app/flag1.txt (in container)
2. /root/flag2.txt (out of container)