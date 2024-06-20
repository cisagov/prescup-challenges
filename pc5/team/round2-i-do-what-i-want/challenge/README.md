# I Do What I Want!

[client](./client) and [server](./server) have been built with fixed token values for the purposes of solving them offline.

Run `client` with the `--test` command line argument (`./client --test`) to force it to connect on `localhost` instead of attempting to connect to a remote system.

If running on a system where the provided binaries are incompatible, the `source` directory contains the full source code of the client and server programs. Reading the source is a major spoiler for the challenge.

In order to compile the client and server binaries, you will need to install the Rust programming language. Follow the instructions on [this page](https://www.rust-lang.org/tools/install) in order to install the required tools. Then, in the `source` directory, run the command `cargo build`. Once the build process is done, you should find the client and server programs in `source/target/debug`.
