# Git in and Git out    

Leverage a vulnerable developer environment and exploit a web server.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform penetration testing as required for new or updated applications.
- [T0171](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform integrated quality assurance testing for security functionality and resiliency attack.


## Background

Given access to a developer machine through SSH, exploit their development environment and retrieve two (2) tokens. The first token is on the web server (`10.7.7.100`) and is presented after gaining administrator credentials. The second token is in a GitLab project owned by `root`.

## Getting Started

You've been given access to a developer machine (`10.1.1.50`). Use the tools available to assess how vulnerable our systems and forward-facing website are to attack if a developer machine should be compromised. There are two tokens to retrieve. Both tokens are six-character hexadecimal strings.

## System and Tool Credentials

| system/tool                   | username | password |
|-------------------------------|----------|----------|
| git-in-kali                 | user     | tartans  |
|10.1.1.50                      | user     | tartans  ||

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. Enter Token 1.
2. Enter Token 2.
