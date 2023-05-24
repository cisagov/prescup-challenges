
# Key to Success

Analyze forensic evidence and find the flag.

**NICE Work Roles:** 

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks:**
- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework) - Decrypt seized data using technical means.
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework) for recovery of potentially relevant information.

## Background

We have found a rogue system running Ubuntu 16 connected to the ACK-ME network. This operating system is not on the approved list of OSes for user systems. We have forensically acquired memory and hard drive images of that system. Your task is to analyze the forensic evidence available and find the flag.


## Getting Started

You can view the [challenge guide](challenge-guide.pdf) here.

You're provided both the memory image (`memdump.mem`) and the hard drive image (`image.dd`) of the Ubuntu 16 system.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc2/individual-a-round3-key-to-success-largefiles.zip)
and extract in _this directory_ to get started.

## Submission Format

The flag is 29 characters long and can be found in `flag.txt`.


Sample answer:

```
abcdefghijklmnopqrstuvwxyzabc
```

