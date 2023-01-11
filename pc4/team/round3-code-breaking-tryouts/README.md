# Code Breaking Tryouts

Perform code breaking, recovery, and reconstruction of data messages to uncover vital threat information.

**NICE Work Roles**
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-forensics-analyst)

**NICE Tasks**
- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0027)- Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.
- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0049)- Decrypt seized data using technical means.
- [T0167](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0167)- Perform file signature analysis.
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0240)- Capture and analyze network traffic associated with malicious activities using network monitoring tools.

## Background

Intelligence operatives have intercepted and collected competition data sent between space pirate faction members and **Space Pirate Command's Cyber Operations Group** (SP-COG). The contents of the recovered data allude to an upcoming meetup event where the best and brightest pirate code breakers will attend (assuming, of course, that they can break or recover the files to learn the location and time). The data recovered contains this vital information but it has been encoded, scrambled, obfuscated, or corrupted.

If we can learn the location of this event, we can capture members of the SP-COG high command and any up-and-coming space pirate code breakers who could jeopardize our operations.

Our techs have made the recovered files available to you. It is up to you and your team to recover what data you can.

## Getting Started

All challenge files can be retrieved from `https://challenge.us/files` from any in-game Kali system. The first file you should review is the competition instructions sent by the SP-COG.

### Objectives

#### Objective 1: Translate the UNICODE messages

Download the **unicode.zip** package. Use the various resource files to recover passcode 1 from the encoded message files.

#### Objective 2: Investigate and Analyze the Mail Log Data

Download the **maillogs.zip** package. Use the various resource files to recover passcode 2 from the encoded and corrupted message files.

#### Objective 3: Investigate and Analyze the Traffic Captures

Download the **traffic.zip** package. Use the various resource files to recover passcode 3 from the corrupted `passcode3.pcap` file.

#### Objective 4: Access the virtualized system and its encrypted container (Objectives 1-3 required)

Use the passcodes to access the encrypted container and retrieve the location of the meetup event.

> **Note:** Be precise when creating a password file for Objective 4. Leverage the hash provided to ensure your password file is accurate. Some text editors may add extraneous characters/whitespace to files. 

## Challenge Questions

1. What is the passcode recovered from the Unicode message problem? (10 alphanumeric characters)  
2. What is the passcode recovered from the maillog/mail messages problem? (10 alphanumeric characters)  
3. What is the passcode recovered from the packet capture problem? (12 hexadecimal characters)  
4. What is the location (star, planet, moon, etc.) of the meetup event for the code breaker competitors?
