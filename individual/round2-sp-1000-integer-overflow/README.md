<img src="../../logo.png" height="250px">

# + Integer * Overflow >>
#### Category: Securely Provision
#### Difficulty Level: 1000
#### Executive Order Category: Secure Programming

## Background
This challenge provides you with real C code files that are used as part of an open source project. Each file will have an integer overflow bug that was, at one time, actually present in the code (all bugs evident in this challenge have since been patched). The flag you submit for this challenge will be the line number on which the bug is found in each file. For example, if the bug occurs on line 23 in file 1 and line 24 in file 2, the flag to submit will be: 23_24

## Getting Started

You will need to run the script `required/download-challenge-files.sh` if you are on Mac or Linux. On Windows, you will either need a Linux VM or to install the Linux subsystem (or some solution for running bash scripts and common Unix utilities).
This script will produce two files in the working directory, `file1.c` and `file2.c`. Review the challenge files to identify integer overflow.

*Note: There may be information such as function calls, variable definitions, etc., that are not contained
in the files provided. Despite this, all of the information you need to solve the challenge is contained within your challenge files.*

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.