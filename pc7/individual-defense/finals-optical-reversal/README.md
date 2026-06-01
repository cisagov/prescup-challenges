# Optical Reversal

The Agency has recovered neural-implant from a captured agent and you are tasked with its analysis. The device, named `null-horizon`, has a userland which actively mutates; when observed, ordinary tools will be shown plausible data however, it may present users with false outputs. Use low-level, indirect inspection techniques to recover "tokens" which demonstrate the boundaries that can be reached within the operating system without it's self destruction. 

## NICE Work Roles

* Cyber Defense Analyst
* Digital Forensics
* Vulnerability Analysis

## NICE Tasks

* [T1496](https://niccs.cisa.gov/tools/nice-framework): Develop reverse engineering tools
* [T0028](https://niccs.cisa.gov/tools/nice-framework): Conduct/support authorized penetration testing on enterprise assets.

## Background
During a Blacklight Program operation, a neural implant’s interface was recovered from a captured agent mid-operation. This implant supports `Horizon OS` which was preserved and transformed into a single analysis virtual machine (VM) for your investigation. Your mission is to extract seven independent tokens proving you reconstructed the implant’s runtime defenses using observer-safe techniques.

## Objectives
In this mission, you're tasked to:
* Establish a low-level link-layer handshake with the implant by reversing its dynamic IP-dependent XOR/MD5 protocol (TOKEN1).
* Retrieve and decode dynamically encoded control frames using the implant’s current IP and the XOR-shift algorithm from the SPEC (TOKEN2).
* Identify and extract a covert DNS-based beacon, passively sniffing UDP/53 traffic to recover the leaked token (TOKEN3).
* Break the RC4-encrypted artifact provided by the implant and recover its plaintext (TOKEN4).
* Reverse the LFSR scrambler on the second artifact to reconstruct its original message (TOKEN5).
* Exploit a timing side-channel, measuring response delays from interactive pulses to reconstruct a bitstream (TOKEN6).
* Perform the final HMAC challenge, using TOKEN6 as the key and a dynamic nonce to derive the last authorization code (TOKEN7).

By completing these objectives, you will be able to give our agency uncanny infromation about the Operating System which will be used in future recovery operations.

## Getting Started

1. Connect to the socket: `nc -vv null-horizon.local 31337`
2. Retrieve the protocol spec: `echo SPEC | nc -uvv null-horizon.local 30415`
3. Work through the stages to recover TOKEN1–TOKEN7.


## Grading
The implant has several "validation" mechanisms which we were able to re-craft into "grading elements". The `help` menu will be of significant use to you during the course of this engagement.

Please note that you must still send validated tokens to the Challenge Platform in order to receive credit for them.

## Token Formatting

Please note that all tokens harbor the following format:

`PCCC{WORD-XXXXXXX}` 

## Additional Notes
This challenge trains real-world anti-forensics awareness: the implant’s userland is intentionally deceptive to illustrate observer effects. The correct approach uses syscall-level truth and runtime memory inspection rather than trusting sanitized userland outputs. Good luck — keep your work contained to the VM and document your process.

## System and Tool Credentials

|system/tool|port|
|-----------|--------|
|implant primary channel| `null-horizon.local`|tcp/31337|
|implant side channel| `null-horizon.local`|udp/30415|

## Notes
Challenge infrastructure and assets not listed in the System and Tool Credentials table are off-limits for this engagement.