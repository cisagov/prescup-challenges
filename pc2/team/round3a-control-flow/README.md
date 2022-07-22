# Gotta Go With The Control Flow


## Background


  In this challenge, you are asked to create clients to communicate with two server programs. One server is written in Python, and the other is written in Rust.


  The Python server has an HTTP API to interact with, while the Rust server uses a custom messaging protocol to exchange information.


  The model solution for this challenge was written in Python 3, but there was no restriction on the language competitors could use.


## Getting Started


  In the [challenge](./challenge/) folder are three files. The [pyservermain.py](./challenge/pyservermain.py) is, of course, the main file for the Python server. The [rsservermain.rs](./challenge/rsservermain.rs) file is the Rust server main file. [opcodes.rs](./challenge/opcodes.rs) is a module containing the opcodes that the Rust server is expecting to come from a client, as well as the function used to interpret an array of bytes coming from the client.


  You will need to host the server programs in [server](./server) in order to work through the challenge. Both of the provided server programs are built for 64-bit Linux. Read and understand the server code, make a client for each, and the flags will be yours!

  Run the Python server with the following:
```
cd server
tar xzf pyserver.tgz
cd main
chmod +x main
./main
```

  Run the Rust server with the following:
```
cd server
chmod +x rsserver
./rsserver
```


## Submission Format


  The flags for this challenge are wrapped 16-character hex strings.


  Example submission:

  ```

  prescup{01234567890abcdef}

  ```
