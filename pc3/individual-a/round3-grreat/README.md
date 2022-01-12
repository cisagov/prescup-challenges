# Grreat!

Remotely triage and clean a system.

**NICE Work Roles:** 

- [Cyber Defense Forensics Analyst](https://niccs.us-cert.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)
- [Cyber Defense Incident Responder](https://niccs.us-cert.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Incident+Responder&id=All)


 **NICE Tasks:**
- [T0175](https://niccs.us-cert.gov/workforce-development/nice-framework/tasks?id=T0175&description=All) - Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation) tasks to support deployable Incident Response Teams (IRTs).
- [T0432](https://niccs.us-cert.gov/workforce-development/nice-framework/tasks?id=T0432&description=All) - Collect and analyze intrusion artifacts (e.g., source code, malware, and system configuration) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.


## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment. 

## Background

You're provided remote access to a system (IP - `192.168.10.10` and hostname - `WIN-GRR-01`) via GRR Rapid Response. Based on the network logs, this system remotely connected to a suspicious IP `100.200.100.200` on 16th September, 2021 using RDP.


## Getting Started

Your first task is to analyze the remote connection to the suspicious IP and answer the following questions - 
1. Provide the username used in connecting to the suspicious remote IP (`100.200.100.200`)
2. Provide the name of the only folder present on the Desktop of the suspicious remote system (`100.200.100.200`)
3. Two files (.exe and .msi) were copied from the suspicious remote system to a folder on the system under investigation. Name the .exe file that was copied over.

Your second task is to clean the system under investigation. For this second task, you will earn points if -

Grading Check 1 - Both files that were copied from the suspicious remote system have been deleted from the system under investigation.

Grading Check 2 - Application is uninstalled (Out of the two files that were copied from the remote suspicious system, one was a Windows installer file (.msi). The .msi application was then installed on the system under investigation. This is the application that needs to be uninstalled.)

The grading results can be accessed from the `analyst` VM by browsing to `http://challenge.us`. Each successful grading check will yield an 8-character hexadecimal string for submission.

## Things to keep in mind -
1. The GRR client is installed on the system under investigation and is reporting to the GRR server.
2. The Grading results URL (`http://challenge.us`) and GRR Web Console (`http://192.168.10.100:8000`) are both accessible from the `analyst` VM. 
3. A wordlist named `rockyou.txt`, and any other tools needed for completing the challenge are available on the `analyst` workstation.
4. Following is some documentation from GRR website on Client-Server communication - 
    _"When a Flow needs to request information from a client, it queues up a message for the
    client. GRR clients poll the GRR server approximately every 10 minutes, and it will 
    receive the message and begin responding to the request at the next poll.
    After a client performs some work, it will normally enter ‘fast-poll’ mode in which it
    polls much more rapidly. Therefore when an analyst requests data from a machine, it might
    initially take some minutes to respond but additional requests will be noticed more quickly."_
    
    <br>In this challenge, the default client poll time has been changed from 10 minutes to 30 
    seconds. So the initial few tasks may take up to 30 seconds, but the subsequent tasks should be much faster. 
5. Try using the browser level refresh button if at times the directory listing does not appear even after using the refresh button within the `GRR Virtual Filesystem`.
6. User `flare` was logged into system under investigation when the RDP connection was made to the suspicious remote system.
7. Grading may take up to 90 seconds.

## System and Tool Credentials

| system/tool | username | password |
  |-------------|----------|----------|
  | analyst  | user     | tartans  |
  | grr-Server     | user     | tartans  |
  | grr-Server web console       | admin    | tartans  |

## Note
Attacking or unauthorized access to challenge.us (192.168.10.200) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
