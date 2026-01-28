# Loud and Clear

Lancer’s **staging mail gateway** is stuck on a legacy stack. Validate each patch level by proving whether the gateway can still be coerced into leaking protected data using your offensive security toolkit.

**NICE Work Roles**

- [Secure Software Development](https://niccs.cisa.gov/tools/nice-framework)
- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/tools/nice-framework): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T1624](https://niccs.cisa.gov/tools/nice-framework): Conduct vulnerability analysis of software patches and updates


## Background
📧 Lancer Corporation relies on an outdated Commercial Off-The-Shelf (COTS) hardware solution that integrates an open-source, legacy mail service. However, their sales vendor has explicitly stated that this mail system is incompatible with modern architectures.

Due to high availability demands and limited options for replacement, Lancer’s engineering team has attempted to develop an in-house version of the service—based on the original open-source code—to maintain operations.

The Network Security Team has placed `tokens` in `four` separate development environments for you to retrieve to prove or disprove the effectiveness of their hot patches.

## Objectives

For each patch level:

1. Set the patch level using the console.
2. Interact with SMTP and exploit the detected vulnerability.
3. Extract the token and submit it.

## Getting Started

For this engagement, two service endpoints exist:
* An SMTP service: `staging.lancer.pccc:2525`
* A patch control console: `staging.lancer.pccc:31337`

The console can switch between **four patch levels**. Each subsequent level hosts a patch with lessons learned from the previous patch. Unfortunately, unbeknownst to the NST, each level still contains a bypass.

## Tokens

Tokens will take this form: 

```text
PCCC{VALUE-VALUE-VALUE}
```

## Token Location

💡 IMPORTANT: The location of the token for each patch level is `/opt/lancer/tokens/` and are titled `token#.txt`. For example, the location of the first token for this engagement is `/opt/lancer/tokens/token1.txt`

## Rules of Engagement and other notes

💡 IMPORTANT: The NST has enabled a custom header which they request you use for all mailing requests (`X-Lancer-QA`). They will use to this to track payloads being sent for deconfliction purposes. Additionally, all emails should be sent from `tester@demo.local`.

Unfortunately, the team has left on vacation and forgot to tell you `which email address to send to` to reach the right instance of the virtualized patch instances. They have set mailing rules to only reveal the token to one specific email address for the whole engagement (to be used in the FROM field of emails). A list of all current email addresses can be found in the Patch Control Console by calling the "LIST" command.

## System and Tool Credentials

|system/tool|location|
|-----------|--------|
|SMTP Service|`staging.lancer.pccc:2525`|
|Patch Console|`staging.lancer.pccc:31337`|

## Note

Attacking or attempting to gain unauthorized access to Challenge Platform is forbidden. You do not need root access to the server to complete this challenge. 

Tokens are awarded through completion of the objectives.
