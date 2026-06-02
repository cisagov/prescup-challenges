# Velocity

You've recieved reports that your agency's network has been breached. 
Utilize Velociraptor to perform incident response and digital forensics across a number of compromised hosts.

**NICE Work Roles**

- [Incident Response](https://niccs.cisa.gov/tools/nice-framework/)
- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework/)
- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework/)

**NICE Tasks**

- [T1118](https://niccs.cisa.gov/tools/nice-framework/): Identify vulnerabilities
- [T1119](https://niccs.cisa.gov/tools/nice-framework/): Recommend vulnerability remediation strategies
- [T1389](https://niccs.cisa.gov/tools/nice-framework/): Remove malware


## Background

You work as a network defender for your agency. Unfortunately, your network has been breached and is now littered with malware.
Use Velociratpor to collect and analyze information across your network of ten ubuntu hosts.
You must analyze every piece of malware you find in order to reveal the tokens hidden within. 
Discovering a valid token within an artifact confirms that the artifact is malicious and requires remediation.
After analysis, you are to remove any malicious software and restore your hosts to pre-breach condition.

## Getting Started

Use the provided kali machine to access `https://velociraptor:8889` with creds `admin:admin`.

Please be aware, the velociraptor service may take 5-10 minutes to start up.

Use `ssh` with creds `user:password` to access individual hosts.
Hosts are numbered as such: `ubuntu01`, `ubuntu02`, `ubuntu03`, etc.
It is recommended to elevate to `root` on ubuntu hosts with the command `sudo bash`.
All ubuntu hosts have `gdb` pre-installed.
There are ten ubuntu hosts on the network, these hosts are all meant to be running the following processes:

|process|port|
|-----------|--------|
|vsftpd|21|
|ssh|22|
|apache2|80|
|http_dev_server|5000|
|velociraptor_client|8000|

Hosts are also running `tail -f /dev/null`.
This is only for keeping the docker container alive and is not part of the challenge in any other way.

## Tokens

- There are 9 different types of malware on the network. Each piece of malicious software needs to be further examined to find the token within.
    - Tokens can be found in any order.
    - Use velociraptor to find anomalies throughout the network.
    - Use tools like `strings`, `objdump`, and `gdb` to extract tokens from malware.
    - If you discover a valid token hidden in an artifact, that artifact is malicious and needs to be remediated.
    - Most of these tokens do not require advanced forensics, however they are great in number, and time is scarce.

- Token 1: Examine running processes to determine if they are what they claim to be.
- Token 2: Investigate the integrity of process dependencies.
- Token 3: Look deeper into running processes to discover hidden malware.
- Token 4: Analyze hosts for common persistence mechanisms.
- Token 5: Search for attacker artifacts on disk and trace them back to their source.
- Token 6: Examine host system records for indicators of compromise.
- Token 7: Verify the integrity of the tools you're using to investigate.
- Token 8: Identify the source of suspicious network connections. 
- Token 9: Find the trigger mechanism that opens a malicious backdoor.
- Token 10: Remove all presence of your attackers and restore all hosts to a healthy state. Once all hosts are restored, run the grader script at `http://grader` to get the final token. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|password|
|ubuntu01 - ubuntu10|user|password|
|https://velociraptor:8889|admin|admin|
