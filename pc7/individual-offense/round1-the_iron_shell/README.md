# The Iron Shell

**NICE Work Roles**

- [Cyber Defense Penetration Tester](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T0047](https://niccs.cisa.gov/tools/nice-framework): Conduct vulnerability scans and recognize vulnerabilities in security systems.
- [T0231](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing as required.
- [T0293](https://niccs.cisa.gov/tools/nice-framework): Analyze encrypted data, encrypted traffic, or cryptographic certificates.
- [T0697](https://niccs.cisa.gov/tools/nice-framework): Exploit system vulnerabilities to elevate privileges.

## Background

You are a hired hacker who's job is to attack a target within an office environment. You have been given access to the network and need to find the machine, enumerate it for vulnerabilities, and attack it to gain root access to it. If you are too loud, you will get kicked from the target and will have to restart your instance.

## Getting Started

You have 4 objectives:

1. Enumerate and exploit an exposed web portal. You know there is an entrypoint at `/ping`
1. Crack `ssh` credentials of a user on the machine.
1. Gain root access to the machine.
1. Exfiltrate sensitive files without tripping any alarms.

You have a provided `wordlist.txt` file located at `http://grader/wordlist`.

To submit the credentials for the ssh machine, you can navigate to `http://grader/` in a web browser.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|password|
|`target`|TBD|TBD|
|`grader`|N/A|N/A|

