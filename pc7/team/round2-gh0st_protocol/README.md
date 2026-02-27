# Gh0st Protocol

A rogue device with nuclear codes. A custom protocol. Four tokens hidden in stateful chaos. Trust nothing — not even the interface.

**NICE Work Roles**
* [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework)
* [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
* [Software Security Assessment](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**
* [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities
* [T1496](https://niccs.cisa.gov/tools/nice-framework): Develop reverse engineering tools
* [T1323](https://niccs.cisa.gov/tools/nice-framework): Analyze network traffic associated with malicious activities

## Background

💥 You have found yourself in a `meeting room` at a remote location, being asked by a rogue arms dealer to reveal nuclear codes in exchange for intel on impending attacks against your nation. 

Your agency has tasked you with intercepting this transaction by creating a "simulated" meeting using operators of our own. Another buyer is having a meeting with the other half of our team; however, their specialist is well versed in decrypting this protocol.

Your mission, should you choose to accept it, will be to impersonate Brian Hunt, whose pretext is service as the nation’s most trusted Nuclear Warfare Operator and custodian of the nuclear codes.

`Gh0st Protocol` was created as an auditing mechanism for the integrity of this critical information; however, it can also serve as a first step toward nuclear war in the wrong hands.

It uses a proprietary, stateful protocol and responds only to designees who perfectly mimic agency communication.

Your mission is to reverse the protocol and extract all four `Gh0st` tokens to reveal the nuclear codes before the `real` meeting concludes.

Expect traps, misdirection, and time pressure.

## Getting Started

The Team has left you a backdoor on a `prison cam` system with information you'll need for your meeting. Begin your mission by logging into it and enumerating all possible vectors (logs, files, etc). Log into `prison-cam` via SSH using the credentials below.

## Token

### Formatting
Valid tokens for this challenge will appear using the following format:

`✅ TOKEN#: PCCC{VALUE}`

In this case, `PCCC{VALUE}` would be what is submitted to the Question section of this challenge for points.

Please examine the question `placeholders` to ensure you are using the correct value for submission.

### Placeholders
Tokens within this challenge have varying formats. Please examine the `placeholders` in the `Questions` section of the challenge for guidance on their appearance.

### Token 1
The "key_hex" cited in the `operations memo` is seeking the value that is the hexadecimal value `without` the 0x. Additionally, the `gh0st node` opcode request only accepts `hexadecimal escape sequence` format. 

### Token 2
Nothing to report.

### Token 3
The format for this token is `PCCC{XXXXXX_YYYYYY_ZZZZZZ}`. This token formatting differs from the others. Please keep note of this during your mission.

### Token 4
Nothing to report.

## Objectives

* Reverse engineer and trigger the handshake sequence for initial access.
* Exploit a logic bug in the protocol’s session validation.
* Perform epoch-based synchronization and defeat a crypto barrier.
* Complete the spy-themed GUI validation by submitting a hash at just the right moment.

## System and Tool Credentials

|system/tool|username|password|hostname|protocol|
|-----------|--------|--------|----|------|
|Prison Camera|brian|hunt|`prison-cam:22`|tcp|
|Ghost Protocol TCP|N/A|N/A|`gh0st-protocol:4000`|tcp/GH0ST|
|Suitcase GUI (Inside the Meeting Room)|N/A|N/A|`http://meeting-room:8080`|http|
