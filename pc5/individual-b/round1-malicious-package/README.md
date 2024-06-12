# Malicious Package

You're sick and tired of getting spam email messages about an "*oppertunity* to work with a great company!" There's no way to unsubscribe from their emails, so you take matters into your own hands.

**NICE Work Role**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/): Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0572](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply cyber collection, environment preparation and engagement expertise to enable new exploitation and/or continued collection operations, or in support of customer requirements.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

Find a way to unsubscribe yourself from those pesky spam email messages.

## Getting Started

Go to `mail.merch.codes` from a gamespace resource. Log in using these credentials: `user | tiredofspam`. You can read the spam email from `work4us@merch.codes`. They always include their Gitea page in the email -- this is a great place to examine their code and see if you can unsubscribe from those emails!

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|Challenger-Kali|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5), `k3s-server` (10.3.3.10), and app-server (10.3.3.3) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the password to get into the custom pip server (devpi)?
2. After successfully obtaining a reverse shell, provide the flag located under `/opt/script.sh` inside the Kubernetes pod.
3. Unsubscribe from the email list via the `spam.db` database, commit and push those changes to the `Work4Us` repository and grade your challenge at `challenge.us` to obtain the last token.