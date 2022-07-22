<img src="../../pc1-logo.png" height="250px">

# + Integer * Overflow >>
#### Category: Securely Provision
#### Difficulty Level: 1000
#### Executive Order Category: Secure Programming

## Background

This challenge provides you with real C code files that are used as part of an open source project. One of the files in
your set will have an integer overflow bug that was, at one time, actually present in the code (all bugs evident in this
challenge have since been patched).

The flag for this challenge was the file name that contains the bug and the line number on which the bug is found.

For example, if the bug occurs in file 1 on line 23, the flag would have been `file1_23`.

## Getting Started

You will need to run the script `required/download-challenge-scripts.sh` if you are on Mac or Linux. On Windows, you
will either need a Linux VM or to install the Linux subsystem (or some solution for running bash scripts and common
Unix utilities).
This script will produce four files in the working directory,
`file1`, `file2`, `file3`, and `file4`.

Look through the challenge files and see if you can find the integer overflow.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
