# It, like, stopped working?

_Solution Guide_

## Overview

This challenge expects competitors to leverage the power of `git bisect` to quickly hone in on a breaking change, or commit. Running `make test` takes a non-negligible amount of time (approximately 100 seconds), so using brute force to simply test all of the 10,000 changes applied since the software was last known to be working isn't feasible. 

This solution guide covers the walk-through on how to solve the challenge and is organized by submission question. 

## Question 1

_Email address for the author of the offending commit_

See the steps outlined below. The author's email address is revealed in the faulty commit.

## Question 2

_Abbreviated (8-digit) commit ID of the offending commit_

Find a working (a.k.a. "good") commit. The challenge guide tells us that the oldest 100 commits are known to be free of the error we're trying to identify. Use `git log` and scroll all the way to the end, to the oldest commits in the repository. Pick one, and
test it:

```
git checkout <old-commit-ID>
make test
```

The expected outcome is something like:

```
...
Building commit <old-commit-ID>, please stand by...
100% ... complete. Testing commit <old-commit-ID>...

Test Successful!
```

Find a non-working (a.k.a. "bad") commit. The easiest thing here is to test the latest commit in the `master` branch of the repository:

```
git checkout master
make test
```

The expected outcome looks like this:

```
Building commit <new-commit-ID>, please stand by...
100% ... complete. Testing commit <new-commit-ID>...

Test Failed!
```

Using basic `git bisect`, execute the following commands:

```
git bisect start
git bisect good <old-commit-ID>
git bisect bad <new-commit-ID>
```

This specifies the interval over which Git should conduct its binary search for the faulty commit. Once the above commands are all executed, Git will immediately and automatically select a commit in the "middle" of this interval, and ask you to test whether the repository is in a "good" (working) or "bad" (broken) state at that commit:

```
make test
...
git bisect good  # if test is successful
```

or

```
...
git bisect bad  # if test fails
```

Continue testing the candidate commits selected by Git, and providing `good`/`bad` feedback, until the faulty commit is identified:

```
<faulty-commit-ID> is the first bad commit
commit <faulty-commit-ID>
Author: Author Name <AuthorName@example.net>
Date: ...

   commit message
```

## Automating `git bisect`

In many cases, building, testing, and `good`/`bad` feedback to `git bisect` may be fully automated.

First, `git bisect start` may be directly provided with the `bad` and `good` commit IDs, respectively, as additional command line arguments:

```
git bisect start <bad-commit-ID> <good-comit-ID>
```

Next, the build/test/feedback cycle outlined in the previous section may be automated using:

```
git bisect run <script> [<script-arguments>]
```

Our script must simply return with a `0` exit code on success (implying `git bisect good`), and with an exit code between `1` and `127` (except for the reserved exit code `125`) on failure (implying `git bisect bad`).

In our case, the following script (`test.sh`) may be used:

```
#!/usr/bin/bash

make test | grep -q Successful && exit 0 || exit 1
```

Start the fully automated bisect:

```
git bisect run ./test.sh
```

...then sit back, relax, and let the computer do all the work of finding our faulty commit!

## Cleaning up

At the end, run `git bisect reset` to restore the repository to its original, pre-`git bisect` state.
