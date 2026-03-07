# Project Overwatch: Compromised

Specter, a rogue insider, has been communicating with unknown actors and hiding his activities 
on an internal workstation. Your task is to uncover his hidden trails, decrypt his communications, 
and extract the secrets he tried to conceal.

Intelligence suggests Specter has been embedding sensitive information on his host in unusual ways, 
blending operational tradecraft with technical misdirection. While the machine looks clean at first 
glance, his activities are buried in encrypted communications, manipulated filesystems, and tampered 
system behavior.

Use your Kali host to connect to Specter's workstation (`shadow-target`) and begin your analysis. 
Experiment, validate anomalies with multiple tools, and think like someone trying to cover their tracks.

**NICE Work Roles**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/tools/nice-framework)
- [Incident Response Analyst](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1060](https://niccs.cisa.gov/tools/nice-framework).
- [T1103](https://niccs.cisa.gov/tools/nice-framework): Conduct forensic analysis of digital evidence and malicious code.
- [T1123](https://niccs.cisa.gov/tools/nice-framework): Identify and analyze anomalous activity.

## Background

Intelligence suggests Specter has been embedding sensitive information on his host in unusual ways, blending operational tradecraft with technical misdirection. While the machine looks clean at first glance, his activities are buried in encrypted communications, manipulated filesystems, and tampered system behavior.

Your mission is to investigate his host thoroughly, recover his secret messages, and identify the methods Specter used to conceal them.

## Getting Started

Use your Kali host to connect to Specter's workstation (`shadow-target`) and begin your analysis. 
Experiment, validate anomalies with multiple tools, and think like someone trying to cover their tracks.

## Tokens

Tokens are formatted as `PCCC{value_??_????}`.

1. **Crawl through the past**
   - Specter used somewhat traditional communications methods with their handler. Find and decrypt the messages to reveal their comms.
2. **01010111 01100001 01101100 01101011**
   - The technical team found an artifact of a USB drive that had previously been used by Specter. The team believes this is one method Specter would deliver intel to their handler. Given the disk image, find the intel (token) that was passed _without mounting the disk_ to the workstation as we are concerned it may contain self-destruct or other malicious mechanisms.
3. **Whois Running**
   - Again, not one to be overly creative in their methods, it was found that Specter used a dedicated exfil workstation to get traffic out of the network boundary. Determine the secrets being leaked.
4. **Static Sprint**
   - Surveillance analysts noted Specter often mentioned "placing critical notes in plain sight," but whenever we searched his workstation, nothing turned up. Colleagues swore they saw him typing file names containing "specter_secret" — yet no such files appear in directories today.
5. **Flying under the radar**
   - Agents at the airport were able to get a quick dump from Specter's phone before he fled. The agents password-protected the dump with `eagle`.  We're not sure exactly how they were using the phone to communicate and/or hide intel.  Review the artifacts and uncover what Specter was communicating through this private channel.

## System and Tool Credentials

| system/tool    | username | password  |
|----------------|----------|-----------|
| `kali-vnc` (workstation) | user | password  |
| `shadow-target` | specter | fieldwork |
| `exfil` | n/a | n/a |

## Note

This challenge is running in the Docker containers (hosts) defined above. 
Do not attempt container breakouts to attack the underlying system or competition platform.