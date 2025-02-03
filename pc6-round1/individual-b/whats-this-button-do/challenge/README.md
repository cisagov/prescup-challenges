# What's This Button Do?

*Challenge Artifacts*

The source directory contains the source code for the client and server artifacts. Reading it is a **SPOILER**.

- [client](./client) and [encode_bytes.py](./encode_bytes.py) were artifacts that were downloadable from `challenge.us` in the live competition. [encode_bytes.py](./encode_bytes.py) is a helper tool that was meant to assist with the required encoding, and may still be useful in the offline version of this challenge.

- [server](./server) was *not* downloadable, and reading its output may contain spoilers. It's recommended to run it in a separate working directory in a terminal that you can hide from view while working on the challenge. When running, it will produce a file named `secret`, which contains the base64-encoded shared secret for part 1. It will also produce another file in the same directory for part 2 (the name of this file is a spoiler).

When approaching this challenge offline, run the [client](./client) program with the `-t` argument to make it connect to localhost. You may also find this to be a useful command for solving the challenge.
