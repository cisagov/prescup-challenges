# Code Osiris

In this exploit development driven challenge, you will create the exploit that inevitably took down a secret underwater facility in what is now being called the "Deep Blue Sea" Incident.

**NICE Work Roles**

- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1091](https://niccs.cisa.gov/tools/nice-framework): Perform authorized penetration testing on enterprise network assets
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities

## Background

🔥 Preceding the events of the Deep Blue Sea Incident, a scientist and exploit researcher receives a chilling email message regarding the safety of his fellow colleagues and is urged to go to the Control Room immediately Upon arriving, you are met with an offer you cannot refuse...

The crime syndicate behind this (yara.*) will spare the lives of your colleagues if you join the clan and assemble a new version of `code_osiris`, their flagship malware with global reach.

## Getting Started

For this challenge, tokens are awarded for either successful exploitation of a target based on the provided instruction set.

The questions for this challenge will guide you through the create of a standard buffer overflow and eventually lead you to exploiting a live facility harboring a vulnerable service that has been identified by the clan.

IMPORTANT: The `recruit briefing` located on the `HQ site` will help you along your exploit development journey.

## Tokens

The format for each token will be as follows: `PCCC{VALUES}`. In most instances, challengers may find the following output:

```text
TOKEN#: PCCC{VALUES}
```

Use this to your advantage when examining the binaries in tokens one and two. Please also note that all tokens are randomly generated.

## Objectives
* Temporarily distract the syndicate by successfully creating a buffer overflow against their old version of code_osiris.
* Next, develop the skills to build version 2 of "code_osiris" using a remote exploit development trainer (program).
* Use the exploit against a nuclear facility to launch a missile and prove your loyalty to the syndicate.

## System and Tool Credentials

|system/tool|host|port|
|-----------|--------|--------|
|code-osiris-hq|lab.yara.hq|tcp/80|
|code-osiris-remote|lab2.yara.hq|tcp/9999|
|*abyssnet|abyssnet.dbs|tcp/unknown|

* Scan and enumerate this target to find the port for the hijacked reverse shell to the compromised ABYSSNET service.

## Note

Attacking or unauthorized access to the Challenge Platform is forbidden. 
