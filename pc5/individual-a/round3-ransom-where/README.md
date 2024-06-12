# Ransom Where?

Remediate a ransomware attack by decrypting files, removing malware, and patching vulnerabilities.

**NICE Work Roles**

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework): Perform analysis of log files from a variety of sources (e.g., individual host logs, network traffic logs, firewall logs, and intrusion detection system [IDS] logs) to identify possible threats to network security.
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework): Capture and analyze network traffic associated with malicious activities using network monitoring tools.
- [T0288](https://niccs.cisa.gov/workforce-development/nice-framework): Perform static malware analysis.
- [T0432](https://niccs.cisa.gov/workforce-development/nice-framework): Collect and analyze intrusion artifacts (e.g., source code, malware, and system configuration) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## Background

Your company was recently the victim of a ransomware attack. It's your job to stop the attack, decrypt the affected files, remove all traces of the malware, and patch the vulnerabilities to prevent and protect against future incidents.  

## Getting Started

Tools to help you recover from the ransomware attack are available for download: `https://challenge.us/files`. Log into any available gamespace resources and begin the mitigation.

## Submission Info

**Important!** SSH connectivity is required for grading and is done with the `root` account. Do not alter any files or configuration for the `root` user. Failed connection to host will result in a failed grade. 

The second and third tokens are received upon passing the grading check on `https://challenge.us`. Both tasks require that the VM's `website`, `user`, and `services` pass the grading check.

**Task 1:** Determine the key to decrypting the files using the tools available to you.

**Task 2:** Mitigate and patch vulnerabilities on each machine to prevent reinfection. This includes:

- Decrypting all files
- Updating or removing files and services vulnerable to, or created by, the ransomware
- Enabling and starting the *systemd* service `website.service` to the company's online shop

**Task 3:** Remove the ransomware and anything else created because of the ransomware after mitigation has been completed.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|
|website|user|tartans|
|user|user|tartans|
|services|user|tartans|
|Pfsense|admin|pfsense|
|Security Onion|admin@so.org|tartans@1|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the key used to decrypt the ransomware?
2. What is the token given from `https://challenge.us` grading after mitigating the vulnerabilities and preventing re-infection? (website, user, and services VM's)
3. What is the token given from `https://challenge.us` grading after removing all traces of the ransomware after completing the mitigation step? (website, user, and services VM's)
