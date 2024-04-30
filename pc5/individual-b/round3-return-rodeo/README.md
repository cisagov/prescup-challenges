# Return Rodeo

Having lost administrative (root) credentials to a server, exploit a vulnerable `setuid-root` binary to get the contents of a protected access configuration file.

**NICE Work Role**

- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0567](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze target operational architecture for ways to gain access.
- [T0664](https://niccs.cisa.gov/workforce-development/nice-framework): Develop new techniques for gaining and keeping access to target systems.
- [T0696](https://niccs.cisa.gov/workforce-development/nice-framework): Exploit network devices, security devices, and/or terminals or environments using various methods or tools.


## Background

Utility programs meant to be executed by regular users, but which also need limited privileged resource access, are marked as `setuid-root`. They are owned by `root` on the file system, with the `setuid` mode flag enabled.

Therefore in execution, the program can act as `root`, with the onus on its author to ensure it is used for legitimate reasons.

The use of `setuid-root` programs is discouraged in current best practices because they can act as a vector for privilege-escalation attacks. When combined with other mistakes made during development (buffer overflows, dead code, etc.) a `setuid-root` program may allow  attackers to gain unauthorized access to resources on the target system.

## Getting Started

You have access to a `kali` workstation. From there, use `ssh` to log into the `server` as a regular user.

Focus your attention on the `/usr/sbin/validate_string` utility normally intended to verify the formatting of various ASCII input strings.

You should be able to "trick" this utility into allowing you to view the contents of a protected configuration file: `/etc/key_data`.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali       |user    |tartans |
|server     |user    |tartans |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. In the `validate_string` binary's address space, what is the name of the function immediately preceding `main`?
2. What are the contents of `/etc/key_data` on the `server` system?
