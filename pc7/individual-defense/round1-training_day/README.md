# Training Day

This is training day. Explore several forensics based training exercises to bring you one step closer to becoming a Specialist. As a part of the Nautical Rapid Response Team (NRRT), you are tasked with completing forensics based training tasks in preparation for testing for Response Recruit (R-2).

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Secure Software Development](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1091](https://niccs.cisa.gov/tools/nice-framework): Perform authorized penetration testing on enterprise network assets
- [T1619](https://niccs.cisa.gov/tools/nice-framework): Perform risk and vulnerability assessments
- [T1624](https://niccs.cisa.gov/tools/nice-framework): Conduct vulnerability analysis of software patches and updates


## Background

As a part of the Nautical Rapid Response Team (NRRT), you are tasked with completing forensics based training tasks in preparation for testing for Response Recruit (R-2).

## Objectives 
* Recover a deleted artifact from an image derived from a recent breach
* Decrypt a binary and decode the base64'd secret.
* Inspect system logs to find a hidden payload 
* Inspect a suspicious packet capture to determine a hidden payload in voice communications

## Getting Started 

To begin, navigate to `http://nrrt.pccc` and retrieve `evidence_collection.tar.gz` from the Title Screen.
This is the file you need to begin your training session.

## Additional Information (Tokens)

The token format for this engagement is:

```text
PCCC{VALUE}
```

### For TOKEN2

The memory dump contains a small structured binary blob embedded at an unknown offset.

The blob begins with a fixed ASCII marker and uses a simple header layout:

[ MARKER | VERSION | KEY | LENGTH | DATA ]

* MARKER (4 bytes) - Identifies the start of the blob (LCM2)
* VERSION (1 byte) - Allows future format changes
* XOR_KEY (1 byte) - A randomized key between 0xA1 and 0xFF
* LENGTH (2 bytes, little-endian) - Length of the encoded payload
* XOR_DATA (N bytes) - XOR-encoded base64 string


No filesystem or executable format is present.
Analysis requires identifying the marker, parsing the header, and decoding the data accordingly.

### For TOKEN4

Please note that fragments will begin with "Part #:".

## System and Tool Credentials

|system/tool|location|
|-----------|--------|
|training-day|`http://nrrt.pccc`|

## Note

Attacking or unauthorized access to the challenge platform is forbidden. `nrrt.pccc` is only used to serve the exercise artifacts that you will need for this challenge.