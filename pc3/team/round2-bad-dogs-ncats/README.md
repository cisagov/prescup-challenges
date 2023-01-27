# Bad Dogs NCats

After a system administrator noticed some abnormal activity on the network, they sent the .pcapng file of the network traffic, as well as a forensic image of one of the machines involved. Decipher the encrypted network traffic as well as locate and identify any threat vectors on the machine.

**NICE Work Roles:**

[Cyber Defense Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

**NICE Tasks:**

- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All) - Decrypt seized data using technical means.

- [T0182](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)- Perform tier 1, 2, and 3 malware analysis.

- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)- Capture and analyze network traffic associated with malicious activities using network monitoring tools.

- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)- Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc3/individual-a-round3-not-that-facile-system-ntfs-largefiles.zip)
and extract in _this directory_ to get started.

## Background
The packet capture provided in the challenge folder contains data encrypted as byte strings. A forensic image of an ubuntu machine that is suspected of sending encrypted traffic can be downloaded from the hyperlink above.
1. Analyze the .pcapng file and decrypt the traffic
2. Analyze the image of the suspect machine to find:
    - The encryption executable, placed in the Documents folder, which must be analyzed and reverse engineered
    - Any threat vectors indicated by the decoded packet capture

## Getting Started

1. A word list, `wordlist.txt`, is present in the challenge folder to use in the event of needing to crack a password. The `traffic.pcapng` can also be found in the same challenge folder.
2. The Ubuntu forensic image should be downloaded from the "Large File" link above.

## Answer Tokens
There are three (3) parts for this challenge. Answer tokens will be 9-12 characters.

**Part 1**: Find the key to the encryption/decryption algorithm. (One of the executable's arguments)

**Part 2**: Find the 12 character token embedded in the encrypted traffic found in the Wireshark capture.

**Part 3**: Find the 12 character token in a text file alongside the threat vector.
