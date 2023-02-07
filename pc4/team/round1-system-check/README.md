# System Check

Before setting off, we need to make sure there are no major security flaws in the ship's systems. Interact with some programs exposed over the network and find the flaws in each.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)


**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0266) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0591) - Perform analysis for target infrastructure exploitation activities.

## Background

Before the Dauntless can set off, we need to check several of its onboard systems to ensure all of them are functioning properly.

## Getting Started

Open the attached ISO and examine the files. Each file contains the source code for a program that is being hosted remotely. Find a vulnerability in each one and exploit it.

The programs are accessible with `nc challenge.us 1234`, `nc challenge.us 1235`, and `nc challenge.us 1236`.

## Submission Format

There are three submissions for this challenge. The submission fields have the labels "Program 1", "Program 2", and "Program 3", and these correspond to the same order as the ports shown above.

Each submission is a 16-character lowercase hex string of the format `0123456789abcdef`.

## Challenge Questions

1. Get the flag from Program 1.
2. Get the flag from Program 2.
3. Get the flag from Program 3.