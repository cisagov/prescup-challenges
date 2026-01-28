# Arcadian

🎨 Embrace your love of rustic art by reverse-engineering a new digital exhibit at the Palace of Versailles, built with the `Rust` programming language.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Software Security Assessment](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities
- [T1496](https://niccs.cisa.gov/tools/nice-framework): Develop reverse engineering tools
- [T1590](https://niccs.cisa.gov/tools/nice-framework): Identify programming flaws

## Background

🎨 As an art and history enthusiast, you encounter a new digital exhibition while touring the Palace of Heracles. Before you can ask about the mysterious laptop on the podium, your tour guide explains that only those with a taste for `Arcadian` (rustic) art are 'chosen' to complete the challenge. You are then guided to the laptop and the rest of the tour attendees patiently watch you engage in this one-of-a-kind experience.

In this challenge, you must reverse a `Rust` binary, discover its hidden tokens, and earn the adoration of the greater art community.

## Getting Started

**Downloading The Exhibit**
To get started, simply navigate to the Arcadian website and download the binary to your preferred operating system to begin the journey.

**Permissions Issues**
If you get an Access Denied message when executing the binary, simply run the following command to activate it:
`chmod +x arcadian`

**Tokens**  
Initially, you will find the binary does not readily provide tokens for successful actions:

```text
e.g. ✅ TOKEN1: <VALUE>
```

**This is intended by the artist.**  

You must use your knowledge of reverse engineering functions to extract `tokens` from the binary in a creative way.

**Stages/Acts**  
Any team member can jump directly to a specific stage by running the binary with the following command:

```bash
./arcadian --stage [1,2,3,4,5]
```

This will take you directly to a specific stage at any time.

**XOR-Shift Algorithm**
An XOR-Shift in this context is defined as incrementing the position of a byte by one. Please view the example below for clarity:

```text
Base XOR Key: 0xA1
Word: APPLE

A would be XOR'd with 0xA1
P would be XOR'd with 0xA2
P would be XOR'd with 0xA3
L would be XOR'd with 0xA4
E would be XOR'd with 0xA5
```

## Objectives
* Find the fragmented token 
* Complete the Dynamic Pointer Maze via automation or reverse-engineering.
* Capture the memory of the binary (in a timely manner) 
* Examine the misconfigured logic behind an application error.
* Decrypt ciphertext using an XOR-shift algorithm


## System and Tool Credentials

|system/tool|location|
|-----------|--------|
|Art Exhibit|`http://exhibit.pccc`|

## Note

Only the binary downloaded from the exhibit is in-scope for this engagement. The web page and underlying infrastructure is out of scope.
