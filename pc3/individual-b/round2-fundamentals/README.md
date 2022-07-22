# Fundamentals

Apply knowledge of how data is represented at the basic level.

## Background

  Sometimes, it's important to understand how data is represented in a computer in order to understand where vulnerabilities can arise.

## Getting Started

  There is a Python script in the `challenge` directory. You can use this script as is, or modify it to your liking. You will need to have the `requests` library installed in a Python 3.6+ environment to use it. As is, it will prompt you to interact with a server that gives a sequence. Your task is to complete each sequence.

## Submission

  The open-source version of this challenge does not return a token. Instead, it will return the text "Successfully completed sequence X" upon supplying the correct sequence, where X is the number of the sequence you solved.

# 64-bit Linux

If running on a 64-bit Linux distribution, you should be able to `cd server`, `tar xzf server_elf64.tgz`, `chmod +x server_elf64` and `./server_elf64` to start the server. Enter the `challenge` directory and confirm that the client connects to the server with `python3 fundamentals-client.py`.

# Building the Server

If not running on Linux, or you want to modify the server source for whatever reason, you will need to build the server. Fortunately, this is pretty easy. Install [rustup](https://rustup.rs/). This will install most of the software needed to build, but you may also need to install the appropriate build tools for your system. If you wanted to build the server on Ubuntu 20.04, for example, you would also need to install the `build-essential` package. On Windows, you will likely need Visual Studio build tools or another build environment.

To test that you have all of the build tools installed, create and build a new Rust project with:
```
cargo new testproj
cd testproj
cargo build
```

If everything is correctly installed, the test project will quickly build and succeed. Once you know that the build tools are installed correctly, change directory to the server source (`solution/server_source`)  and `cargo run`. This will build the server code and then run it.

# Solution Script

You will need a Python 3.6+ environment with the `requests` library installed. This may be installed by default, depending on your installed version. Then run the solution script with `python3 solution/fundamentals-solution.py`.