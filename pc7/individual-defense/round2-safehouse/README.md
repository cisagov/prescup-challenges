# Safehouse

The art of Deception in full view. Safehouse is compromised. Stay frosty. 

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework)
- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploit Analysis](https://niccs.cisa.gov/tools/nice-framework)


**NICE Tasks**

- [T1091](https://niccs.cisa.gov/tools/nice-framework): Perform authorized penetration testing on enterprise network assets
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities
- [T1383](https://niccs.cisa.gov/tools/nice-framework): Utilize deployable forensics toolkit

## Background

🕴️ The agency’s internal agent listing database called “Safehouse” is rumored to contain sensitive operational blueprints and details about previous operations. You’ve gained access to the frontend of the application but need to acquire administrative credentials to start your investigation. Each token you retrieve signifies a step towards revealing the true intent of this secret agency supporting its existence. 

## Tips

### General
Enumeration is key. Look for misconfigurations in the web server as well as backup files that may have been left inadvertently (.bak). Everything you need to complete this challenge is within your view. 

### Token 4
The `LOCATOR` offset is unreliable in this capture. The encrypted bytes begin immediately after the `end_of_capture` marker. The size remains stable.

## Getting Started

To get started, simply navigate to your Operator's Dashboard located at `http://safehouse.local:3000` to begin the challenge.

## Tokens 

### Token Formatting

✅ *Valid tokens** for this challenge use the following format: `PCCC{SFH-XXXXXX}`. 
❗ Other tokens discovered without this format should be deemed as adversarial artifacts to distract you from your operation's objectives.

### EOCD Forensics (Token 3)

When discovered, the format of `cmt-k` will be two characters or digits. This is a `hex` value (0xYY) that can be used to XOR against the encrypted file found in each dead drop archive. Each archive is unique.

## System and Tool Credentials

|system name|location|
|-----------|--------|
|Safehouse Records Portal Frontend|`http://safehouse.local:3000`|

## Note

Attacking or unauthorized access to the challenge platform is forbidden.