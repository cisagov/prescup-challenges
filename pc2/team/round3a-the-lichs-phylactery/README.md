# The Lich's Phylactery

Assess and reverse-engineer a rapidly spreading novel ransomware.

**NICE Work Roles:**
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**
- - [T0049](https://niccs.cisa.gov/workforce-development/nice-framework) - Decrypt seized data using technical means.
- - [T0103](https://niccs.cisa.gov/workforce-development/nice-framework) - Examine recovered data for information of relevance to the issue at hand.
- - [T0113](https://niccs.cisa.gov/workforce-development/nice-framework) - Identify digital evidence for examination and analysis in such a way as to avoid unintentional alteration.
- - [T0286](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform file system forensic analysis.



## Background

It's been a long day in the forensics lab at CERT when Rob rounds the corner and approaches with a particularly worried face. "I don't know who else to ask, this one is looking ugly, and you just happen to have some experience in this area. This thing locks user files in a very particular way. We've never seen it before. Its ransomware of some sort, but has no precedent. It's popping up everywhere."


Can you assess how the files have been locked? Determine how they have been locked? Reverse-engineer their locking mechanism? Restore the files?


While Rob anxiously awaits your answer, you glance at your music player.


"This is gonna call for something heavy, Rob..."


## Getting Started

Mount [phylactery.iso](./phylactery.iso) on a Linux or Mac system. Explore the mounted file system and find challenge artifacts. Installing and using Python (any version still supported) or another scripting language may be helpful for this challenge.


## Submission Format

There are just two flags in this challenge. Once you determine the files in play, and the location of the encrypted payloads, you will find the **first flag** in this general vicinity.


The **second flag** will be found in a file derived from a particular set of files, via decrypting them in their entirety. Both flags are in all caps and use underscore characters for spaces.


## Example Submission


Flags will be in `{curly braces}`.


**Part 1/2** - First Flag

```

A_POTENTIAL_FLAG_MIGHT_LOOK_LIKE_THIS

```


**Part 2/2** - Second Flag

```

ANOTHER_FLAG_COULD_BE_THIS

```
