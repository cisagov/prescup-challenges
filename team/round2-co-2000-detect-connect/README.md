<img src="../../logo.png" height="250px">

# Detect Connect
#### Category: Collect and Operate
#### Difficulty Level: 2000
#### Executive Order Category: Reverse Engineering

## Background

During the challenge, participants were given a Windows VM with some common malware analysis tools on it, such as IDA
Free 7.0 and x32dbg/x64dbg. The obvious challenge file was sitting on the user's desktop named `origins.exe`. This
challenge relied on having some files seeded across the file system, and so opening this challenge to the public would
remove the aspect of finding some parts of the challenge.

We have included the challenge executables in the `solution` folder for those who would still like to perform analysis
on them, but they have been recompiled in order to generate the PDB files that are also in that directory. The
underlying assembly may vary slightly from the executables on the challenge VMs, and in some cases they expect files to
be present in a particular location and otherwise do nothing.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.