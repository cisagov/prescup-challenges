# Report Back

Shipments from Slurp Industries keep getting intercepted by Space Pirates. We don’t know how, but we suspect an employee on the inside is being careless. We think this employee is downloading malicious files which then grant Space Pirates access to their workstation and confidential shipping route information.

Find the careless employee to prevent other shipments from getting lost!

**NICE Work Roles** 

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)
- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/vulnerability-assessment-analyst)

**NICE Tasks**

- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0570) - Apply and utilize authorized cyber capabilities to enable access to targeted networks.
- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0641) - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0028) - Conduct and/or support authorized penetration testing on enterprise network assets.

## IMPORTANT
This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

We believe that a Slurp Industries employee is carelessly downloading and executing email attachments from their manager without checking if the files are safe or malicious. This insider threat is allowing the Space Pirates to intercept Slurp Industry shipping route IDs.

You must use **Telnet** to send malicious attachments via email to Slurp Industries employees. The email server is hosted on `10.5.5.96`.

**Caution!** Using other methods of _sending_ email will **not** work. You can scan for other ports/services that might help you navigate through email more easily.

You can send email from any email address you choose via Telnet; however, the insider threat only executes attachments sent to them by their manager.


## Getting Started

Use Telnet to connect to the email server on `10.5.5.96`. Login as `human@merchant.caste.aurellia` using the provided credentials. 

Your email inbox contains an email with further instructions and a shipping report attached. Use the shipping report to determine who the insider threat might be. Then, using the email address of the insider threat's manager as the `from` address, send the insider threat a malicious email attachment that will grant you remote access to their machine. 

Once you gain remote access to the employee's machine, you must find shipping route IDs in their documents, emails, and other common places. 

## Submission Format

This challenge consists of several parts.

**Part 1**

Find and submit the insider threat's username. Send this username in an email from `human@merchant.caste.aurellia` to `admin@merchant.caste.aurellia` to receive further instructions for completing the next parts of the challenge. 

**Parts 2 - 7**

Use your access to the insider threat's machine to discover the six unique shipping route IDs that the employee handles. These can be found by looking through the user's files and emails (sent and received). The user may have had root access to their machine, so look in `/root` too. 

Send Route IDs that you discover on the employee's machine via email from `human@merchant.caste.aurellia` to `admin@merchant.caste.aurellia`.  The admin's reply will contain a token to submit for each discovered Route ID. 

## Challenge Questions

1. What is the username of the employee responsible? 
2. Token-1 (received via email from `admin@merchant.caste.aurellia`)
3. Token-2 (received via email from `admin@merchant.caste.aurellia`)
4. Token-3 (received via email from `admin@merchant.caste.aurellia`)
5. Token-4 (received via email from `admin@merchant.caste.aurellia`)
6. Token-5 (received via email from `admin@merchant.caste.aurellia`)
7. Token-6 (received via email from `admin@merchant.caste.aurellia`)


## Tips

Usernames and emails are *not* the same. Emails look like this: `admin@merchant.caste.aurellia`; usernames look like this: `admin-abc123`. 

After sending your first email, you will receive an `email.log` file located on your Desktop. This log file helps you track and provide some basic feedback on all emails/attachments you send. Take advantage of it!

**Caution!** This log file requires that SSH remain available on the provided `laptop` Virtual Machine. Do not disable SSH, change passwords, or remove SSH Keys on this VM or you will lose log data.


