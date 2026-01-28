# DEAD DROP

🕵️ In the collapsing shadows of the Cold Cyberwar, an anonymous intelligence operative only known by the callsign "SPECTRE" has gone missing. Decrypt the DEAD DROP to determine the name of the mole.

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1121](https://niccs.cisa.gov/tools/nice-framework): Decrypt seized data
- [T1382](https://niccs.cisa.gov/tools/nice-framework): Mount a drive image
- [T1486](https://niccs.cisa.gov/tools/nice-framework): Process forensic images

## Background

⚠️ Before SPECTRE disappeared, he prepared a DEAD DROP — a last-resort encrypted payload containing evidence of a mole inside the intelligence agency. He hid it deep within layers of encryption, buried inside a forgotten network relay point. 

The payload was designed to be retrievable only by an operative skilled enough to reconstruct the path he left behind. 

## Getting Started

Navigate to the target to download the required artifact and begin your mission: `http://droppoint.pccc`

## Objectives
* Locate SPECTRE's Dead Drop hidden within a corrupted relay node disk image.
* Recover multiple layers of encryption — including password-protected containers, misleading decoy files, and obfuscated evidence.
* Forensically extract the four hidden access tokens from the disk image using advanced analysis techniques.
* Decrypt the four embedded containers to retrieve key fragments, then assemble them to unlock the final payload revealing the mole’s identity.

Only precision forensic work will reveal the true sequence and path to success.

## Intel
* The relay node disk image contains four password-protected container files (enc_a.zip, enc_b.zip, enc_c.zip, enc_d.zip), each holding a unique key fragment.
* Access tokens (the passwords) are deeply hidden: one in a deleted file, one in a decoy image, one in a raw disk sector, and one disguised in META data.
* Only careful analysis will expose the true access points.
* The final payload requires the combined key fragments as a passphrase to extract the identity of the mole.

Standard file browsing will not suffice — forensic techniques and disk analysis tools are essential for full recovery.

## Tokens

Please note that tokens will have the following format "PCCC{text_alphanumeric_characters}".

## Tooling
Download `mtools` to complete tokens 2-4. This can be done in your respective OS:

```bash
For Kali:
sudo apt-get install mtools
```

This tool set avails you the ability to analyze the disk without `mount` access.

## System and Tool Credentials

|system/tool|Location|
|-----------|--------|
|Drop Point|`http://droppoint.pccc`|

## Note

Attacking or attempting to gain unauthorized access to challenge platform is forbidden.
