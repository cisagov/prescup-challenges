# Fun with Distributed Systems

*Challenge Artifacts*

- The [source](./source/) directory contains the source code for the distributed network used in this challenge. Reading it is a **SPOILER**.

- The [executables](./executables/) directory contains the executables used in the challenge. [part1](./executables/part1) and [hidden1](./executables/hidden1) are used in part 1, while [part2](./executables/part2) and [hidden2](./executables/hidden2) are used in part 2. The `hidden` executables have additional functionality to get the challenge token from the local system, which is not strictly necessary for offline completion, but may help to indicate when the challenge is solved.

- The [known_peers](./known_peers) file also contains the public/private key pairs used in the challenge, which is also a spoiler if used to solve the challenge. The [hidden2](./executables/hidden2) executable was running five instances during the competition, with each instance provided one key pair from this file using `sed -n "1 p" known_peers`, `sed -n "2 p" known_peers`, and so on, to pull a line from the file.
