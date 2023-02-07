# Keep Persisting!

The Dauntless 'Policies and Procedures for First Contact' website has been defaced by **XeNO**! After a few attempts on bringing the website back, it keeps defacing! The crew isn't ready for any unplanned first contact so, it is your job to fix it and bring it back to normal.

**NICE Work Roles** 

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-incident-responder)

**NICE Tasks**

- [T0163](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0163) - Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.
- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0175) - Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation) tasks to support deployable Incident Response Teams (IRTs).


## Background

On a routine check of the webserver, you discovered that the 'Policies and Procedures for First Contact', hosted on IP address `10.5.5.130`, has been defaced. Trying to restore it using the backup on the `responder` VM's Desktop, you noticed there's some persistence mechanism that keeps defacing the website. Find those persistence mechanisms, remove all signs of them and restore the website to its original state from backups!

## Getting Started

Your goal is to **remotely** clean your webserver from any persistence and restore it using the provided backup on the `responder` VM's Desktop. To do so, you will need to: 
1. Using the credentials below, remotely access your webserver on the 10.5.5.130 IP address.
2. Remove/delete **ALL** traces of persistence that keeps defacing your website. This might be files, folders, scripts and more! 
3. Restore the website using the backup on the `responder` VM's Desktop.

## Challenge Questions
The grading results can be accessed from the `responder` VM by browsing to `https://challenge.us` inside of the challenge environment. Each successful grading check will yield an 16-character hexadecimal string for submission.

1. Remove persistence mechanism 1
2. Remove persistence mechanism 2 
3. Remove persistence mechanism 3
4. Remove persistence mechanism 4
5. Fix the website so it is no longer defaced


