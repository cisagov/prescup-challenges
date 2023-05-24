# Going for Silver


Create silver tickets to compromise the system.

**NICE Work Roles:**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

    
**NICE Tasks:**  

- [T0549](https://niccs.cisa.gov/workforce-development/nice-framework).
- [T0572](https://niccs.cisa.gov/workforce-development/nice-framework) : Apply cyber collection, environment preparation and engagement expertise to enable new exploitation and/or continued collection operations, or in support of customer requirements.

## Note

  The following challenge guide is included with no alterations from the version in the competition. This challenge has no artifacts that can be made available to the public. You can play a full version of this challenge on the hosted site.

## Background

You are provided a domain-joined Windows 10 VM and a Kali VM on the same subnet as the domain. The domain in this environment is `prescup.local`. 

We have retrieved the NTLM hashes of the some of the accounts on the Domain. We dumped them into the domain Guest account comments so you will be able to query the account and view the hashes.

Your job is to create silver tickets for the CIFS, LDAP, and HOSTS services in order to read from SYSVOL, create a computer account on the domain, and create a scheduled task on the DC.

## Getting Started

Use the provided Impacket scripts on Kali and the provided Mimikatz binaries on Windows. Start by querying LDAP anonymously for the Guest account's comments. Afterwards, find the SID of the accounts on the domain. Use this information to create silver tickets to complete the tasks. Please use the README on the desktop.

## Submission Format

There are three different submission tokens for this exercise:

- Token for accessing the SYSVOL folder
- Token for creating the Computer Account "Win10-Fake" in AD
- Token for creating the scheduled task "PresidentsCup" on the DC

The tokens will show in the file `\\tokyo.prescup.local\sysvol\token.txt`

Find these tokens and submit them as the answer to the relevant questions.

## System Credentials

  | System      | Username | Password |
  | -------------- | -------- | -------- |
  | Kali   |  user  | tartans |
  | Win10  |  prescup  |  tartans@1  |
