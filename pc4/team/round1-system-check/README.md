# System Check

Before setting off, we need to make sure there are no major security flaws in the ship's systems. Interact with some programs exposed over the network and find the flaws in each.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.

## Background

Before the Dauntless can set off, we need to check several of its onboard systems to ensure all of them are functioning properly.

## ⚠️ Large Files ⚠️
 This challenge includes large files as a separate download. Please download the required files from [here](https://presidentscup.cisa.gov/files/pc4/team-round1-system-check-largefiles.tar.gz) and follow the instructions in the [challenge/server directory](./challenge/server) to configure the server needed for this challenge. The zipped file is ~92MBs and will be imported into `Docker`.

## Getting Started

Open the [challenge directory](./challenge) and examine the files. Each file contains the source code for a program that is being hosted remotely. Find a vulnerability in each one and exploit it.

The programs are accessible with `nc localhost 1234`, `nc localhost 1235`, and `nc localhost 1236`.

## Submission Format

There are three submissions for this challenge. The submission fields have the labels "Program 1", "Program 2", and "Program 3", and these correspond to the same order as the ports shown above.

The offline version of this challenge uses the string `Success!` in place of flags.

## Challenge Questions

1. Get the flag from Program 1.
2. Get the flag from Program 2.
3. Get the flag from Program 3.
