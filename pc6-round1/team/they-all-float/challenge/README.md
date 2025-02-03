# They All Float Down Here

*Challenge Artifacts*

The [server](./server/) directory contains the source code for the server that users interact with for this challenge. Reading its source code is a **SPOILER**. In order to build and run the server, [install Rust](https://www.rust-lang.org/tools/install), enter the `server` directory, and run `cargo run --release`. It will listen on all local interfaces.

[curl_command.sh](./curl_command.sh) exists to make it more convenient to interact with the server. It requires the `curl` program to be installed. It requires three arguments to be provided - the first argument is the part number to attempt (1-4), and the second and third arguments are the pair of values to be submitted to the server for that part.