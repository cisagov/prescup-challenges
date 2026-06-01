# Wargames

*Challenge Artifacts*

This README file contains details on how the challenge was created. 

### server

Contains the files for the `WOPR` server.

- [app/](./server/app): Contains the C code and a runner for the program.
  - [app/main.c](./server/app/main.c): The vulnerable C code.
  - [app/run_demo.sh](./server/app/run_demo.sh): A simple bash runner that redirects stderr to a location where it can be monitored by `supervisord`.
- [conf/](./server/conf): Contains the configuration files for `supervisord` and `xinetd`.
- [Dockerfile](./server/Dockerfile): The Docker file for the server.
  - It builds and compiles against a specific version of `glibc` to ensure the offsets are consistent. If the version becomes unavailable, the general process should still work with new offsets.
  - It also installs `nginx` to host the artifacts for download.
- [entrypoint.sh](./server/entrypoint.sh): A simple entrypoint script that loads the tokens from the environment and then runs `supervisord`.

## Challenge Environment Initial Setup Requirements 

This challenge is run entirely using Docker and Docker compose, so start up is very straightforward.

### Installing Docker

First, install Docker and Docker compose, using the official docker instructions for whichever operating system you are using. The entire challenge can then be launched easily using 

`docker compose up -d`

TODO: Add any details about getting in? Maybe VNC?

### Grading

This challenge does not involve grading.
