<img src="../../logo.png" height="250px">

# Johny Doesn't Know Security
#### Category: Collect and Operate
#### Difficulty Level: 500
#### Executive Order Category: Cyber Exploitation

## Background

During the competition, the flag for this challenge was on a remote system. Your task was to break into that system and
get the flag from the root user's home directory.

In order to succeed at this challenge, you will need to understand the following topics:
* Network scanning
* Fuzzing
* Buffer Overflow
* x86 Shellcode
* Privilege escalation

## Getting Started

To adapt the challenge for public consumption, we have created a setup script under the `required` directory as well as
packaged the supporting files. Competitors did not have direct access to these files during the competition, and so if
you want to avoid challenge spoilers, you should avoid peeking at the contents of anything under `required`.

In order to set this challenge up, you will need to create a Linux VM (Ubuntu 18.04 was used for this purpose during the
competition). Once this VM is running, place the contents of `required` into the root home directory (`/root`) and run
`setup.sh` as `root`. This may take several minutes, since the script needs to ensure that the libc6-i386 package is
installed (32-bit libc). Once the setup is complete, you will need to make sure you can remotely access this VM from the
system on which you intend to do the challenge (Kali was given for this challenge).

In addition to the above setup, the `johny-inventory` executable requires the `ld-linux.so` library to run. On Ubuntu,
this library is part of the `libc6-i386` package and installing that package will suffice if you want to use Ubuntu to
debug the challenge. Kali 2020.1 has this library installed by default.

To get started, scan for any open ports on your configured target system.

If the remote server crashes, it will restart within a minute.

## Disclaimer

**DO NOT RUN THE `setup.sh` SCRIPT ON ANYTHING BUT A THROWAWAY SYSTEM.** This script intentionally creates
vulnerabilities on the system it runs on.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.