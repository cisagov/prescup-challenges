# The Art of the Heist

Your crew is planning an epic heist! The target is a digital safe known only as the **Vault**. Use your skills and experience to exploit network vulnerabilities, bypass the Vault's security, and crack the Vault.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0228](https://niccs.cisa.gov/workforce-development/nice-framework/): Store, retrieve, and manipulate data for analysis of system capabilities and requirements.
- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply and utilize authorized cyber capabilities to enable access to targeted networks.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis for target infrastructure exploitation activities.
- [T0695](https://niccs.cisa.gov/workforce-development/nice-framework/): Examine intercept-related metadata and content with an understanding of targeting significance.

<!-- cut -->

## Background

Your crew is preparing for its last heist. The target is the Vault: a secure digital safe hosted at `vault.merch.codes`. Rumor has it that the Vault contains something of extremely high value. Gain access to the Vault and retrieve whatever that may be.

Intel on the Vault includes:

- Low-level credentials to the firewall
- Information about the network layout
- Information about the Vault's authentication method
- Information about the Vault's security personnel

Intel also includes the document,`instructions.txt`, which provides additional details about the Vault. 

## Getting Started

In the gamespace, browse to `challenge.us` and download the file `instructions.txt`. Review `instructions.txt`, enumerate the network, gain access to the Vault.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|heist-kali|user|tartans|
|pfsense.merch.codes (10.0.0.1)|bookworm|read-only|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the hex string found on `vault.merch.codes` after successfully logging in?
2. What is the hex string found on `vault.merch.codes` after successfully passing all stages of authentication?
