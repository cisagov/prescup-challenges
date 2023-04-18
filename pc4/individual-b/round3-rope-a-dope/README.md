# Rope-a-Dope

After the Dauntless experienced a mysterious power surge, you realize an emergency update to its ECM software (running on a server named `cube`) is
needed. However, the root password to `cube` has been lost, and the only crew member who remembers it has been knocked unconscious during the
incident and is currently on life support in sick bay. You have an unprivileged shell account on the `cube` server, and must use your
offensive security skills to execute a privilege escalation attack and recover root access to `cube`.

**NICE Work Roles:**
- [Cyber Operator](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/workroles?name=Cyber+Operator&id=All)

**NICE Tasks:**
- [T0567](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0567&description=All) - Analyze target operational architecture for ways to gain access.
- [T0664](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0664&description=All) - Develop new techniques for gaining and keeping access to target systems.
- [T0696](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0696&description=All) - Exploit network devices, security devices, and/or terminals or environments using various methods or tools.

## Background

Utility programs meant to be executed by regular users, but which also need (limited) privileged resource access, are marked as `setuid-root` (i.e.,
owned by `root` on the file system, with the `setuid` mode flag enabled). This means that, in execution, the program can act as `root`, with the onus
on its author to ensure it only uses its powers for *legitimate* ends.

The use of `setuid-root` programs is discouraged in current best practices, as they have been known to act a vector for privilege escalation attacks.
When combined with other mistakes committed during program development (e.g., buffer overflows), the program might end up allowing an attacker to gain a `root` shell on the target system.

## Getting Started

_Note: For completing this challenge offline, please see the instructions in the [challenge directory](./challenge)._

You are given access to a `kali` workstation. From there, use ssh to log into `cube` as a regular user.

Focus your attention on the `/usr/sbin/chk_cube_cmd` utility, normally intended to verify the formatting of command strings for the cube drive.

You should be able to "trick" this utility into launching a root shell on the `cube` server, which would then allow you to read the contents of
a file named `/root/token.txt`, which contains the the final (and most highly valued) portion of your submission.

## Challenge Questions
1. What is the offset (in decimal bytes, relative to the start of the overflowing buffer) of the vulnerable function's caller's return address?
2. What is the content of `/root/token.txt` on the `cube` server?
