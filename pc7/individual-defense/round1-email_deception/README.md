# Email Deception

Identify email artifacts and deduce information.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T0160](https://niccs.cisa.gov/tools/nice-framework): Detect and analyze anomalous activity.
- [T0004](https://niccs.cisa.gov/tools/nice-framework): Analyze email headers, logs, and metadata to determine source authenticity.
- [T0357](https://niccs.cisa.gov/tools/nice-framework): Monitor system logs for signs of malicious activity.


## Background

You are an administrator of the email system. Users have been reporting suspicious emails from what looks like real sources. Your job is to:

1. Identify the email server software versions.
1. Identify any emails that did not come from an authenticated source.
1. Set the DMARC record to reject unauthenticated emails.
1. Find any suspicious attachments or links in any emails and gather any information you can from them.

## Getting Started

Using the provided Kali machine, you must access the environment to gather the information required for the tasks.

Emails are @mail-auth.example.com

To acquire the token for the DMARC record, you must navigate to `http://grader/` using a web browser.

## System and Tool Credentials

|machine|username|password|
|-------|--------|--------|
|kali|user|password|
|dns|user|mailman|
|mail_auth|user|mailman|
