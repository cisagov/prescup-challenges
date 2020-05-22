<img src="../../logo.png" height="250px">

# Not Suspicious At All. At. All.
#### Category: Collect and Operate
#### Difficulty Level: 2000
#### Executive Order Category: Software Reversing

## Background

This morning, a VIP within our company accessed his computer and found that all of his files seemed to be corrupted.
Upon further investigation, we determined that they were likely encrypted by some form of malware intentionally, because
there was a single executable file on his desktop that was not encrypted. We don't know what it does, and we'd like you
to find out.

## Getting Started

You will need standard malware reverse engineering tools to work through this executable. While solving the challenge,
you will need to explore code paths that seem like dead code.

This challenge originally was mistakenly linked against debug versions of runtime libraries. This executable has been
recompiled to link against release versions of the same libraries.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.