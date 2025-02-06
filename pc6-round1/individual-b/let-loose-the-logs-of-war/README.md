# Let Loose the Logs of War

Cry "Havoc!", and exploit a web server running in a Docker container to retrieve tokens.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Vulnerability Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework): Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework): Perform analysis for target infrastructure exploitation activities

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Getting Started

Navigate to `10.5.5.100` and probe for any vulnerabilities in the web server. Use the **Wordlist.txt** from the CDROM on the Kali VM to perform a brute force attack with the username *Admin*. Once you've gained access, explore the system to uncover and retrieve the two tokens. Both tokens are eight-character hexadecimal strings.

## Challenge Questions

1. Enter Token 1 found in the `/` directory of the web server container.
2. Enter Token 2 found in the `/home/user/` directory of the host system after breaking out of the Tomcat container accessed in Question 1.