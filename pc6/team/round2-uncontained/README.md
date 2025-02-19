# Uncontained

Complete four different Docker hardening challenges. Run the containers and submit for grading.

**NICE Work Roles**

- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Secure Software Development](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1108](https://niccs.cisa.gov/workforce-development/nice-framework/): Evaluate interfaces between hardware and software
- [T1563](https://niccs.cisa.gov/workforce-development/nice-framework/): Implement system security measures


<!-- cut -->

## Background 

A business has implemented a base Docker host with web application and database containers for testing. However, they forgot to implement proper security configurations on the Docker host. Your job is to implement a list of specific Docker Container security configurations.

## Getting Started 

Using the provided Kali machine, you may use `ssh` to login to a Docker Host machine by invoking `ssh user@docker-host1`.

To grade your challenge and acquire the tokens, you must use a browser to go to `https://challenge.us`

To get a token, the containers must be running with the proposed configurations.

There is a web application image and database image available to satisfy the conditions.

There is a base image on `docker-host2` named `token` that you can use for part 4.

This challenge has 4 parts:

## Part 1: Docker Daemon and Sudo on docker-host1
- Enable user namespace remapping on the Docker daemon.
- Enable Docker to be run without using sudo.

## Part 2: Resource limits and Seccomp Profile on docker-host1
- Enable resource limits of 1GB of RAM, 1CPU, and a Blk IO Weight of 100 on all running containers.
- Implement a seccomp profile on all containers that allows all system calls by default except for explicitly returning an error code when calling the `ptrace` system call.

## Part 3: Docker Isolated Network on docker-host1
- Create an isolated network between the web app and the database container, ensuring not to expose the database to the external network.

## Part 4: Logging
There is a second Docker host named `docker-host2` where you will need to create a docker image to be used as a syslog server. This can be done independently from interacting with `docker-host1`.
- Create a custom Docker image and deploy a container on `docker-host2` that will accept simple syslog connections. The `token` image is available to you on this machine to complete this task.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-challenger|user|tartans|
|docker-host1|user|tartans|
|docker-host2|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.