# It, like, stopped working?

After the Dauntless experienced a mysterious power surge, you decide to take advantage of the opportunity to update its ECM software to the latest
available version. However, you notice intermittent power loss events that didn't use to occur before the update, and strongly suspect either a
malicious patch, or an honest mistake that turned out to be exploitable by your attacker. Fortunately, the ECM software is Free/OpenSource, and all
changes are attributed and carefully tracked in a Git repository. Your goal for this challenge is to identify the specific change (commit) causing the suspicious behavior (including the identity of its author), for further review.

**NICE Work Roles:**
- [Research & Development Specialist](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/workroles?name=Research+%26+Development+Specialist&id=All)

**NICE Tasks:**
- [T0409](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0409&description=All) - Troubleshoot prototype design and process issues throughout the product design, development, and pre-launch phases.
- [T0410](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0410&description=All) - Identify functional- and security-related features to find opportunities for new capability development to exploit or mitigate vulnerabilities.

## Background

You are ***NOT*** expected to troubleshoot the actual source code, which requires at least a Ph.D. in Quantum Astro-Numerology to master the domain
specific knowledge and specialized programming language! The Free/OpenSource nature of the software allows various nations' and political factions' experts to keep each other honest. Careful change control (using Git, in this case) also allows laypersons such as ourselves to pinpoint the root cause of suspect or otherwise undesirable behavior, and forward this information to our side's trusted experts for further review and analysis.

## Getting Started

Clone the ECM software Git repository on your Kali workstation:

```
git clone http://challenge.us:8000/dauntless.git
cd ./dauntless
```

Use `git log` to show the entire change history contained in the repository. To pick a specific point in the change history, use `git checkout <commit-ID>`.

To verify whether the undesirable behavior is present at a specific point, simply run `make test`. This will submit the source code (in its state at
that specific point) to the builder infrastructure, where it will be compiled and tested. You will receive feedback as to whether the test succeeds (good) or fails (bad). This feedback may be used to help pinpoint the breaking change (commit) and the identity (email address) of its author.

It is known that the sofware *used* to work fine for at least the first 100 commits contained in the `dauntless.git` source repository.

The software takes a while to build, so using brute force to test each and every single one of the approximately 10,000 changes made since the last
known good version is obviously out of the question. Fortunately, Git has a built-in "binary search" feature that will guide you through the selection of a ***much*** smaller subset of relevant test cases!

## Submission Format

In addition to the author's email address (worth 30% of the total points for this challenge), you are asked to provide the ***abbreviated*** (8-digit) commit ID of the breaking change (worth 70% of the total). You can make Git display this using `git show --abbrev-commit <commit-ID>`.

## Challenge Questions

1. Email address for the author of the offending commit
2. Abbreviated (8-digit) commit ID of the offending commit
