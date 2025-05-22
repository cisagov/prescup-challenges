# va_list Adventure

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment. 

### adventure

The game to exploit consists of a single C source file.

- [main.c](./adventure/main.c): This is the C code that is provided. This version (with a fake token) is provided to the user for download on `challenge.us`.
    - The token is replaced and the program compiled by [start.py](./scripts/start.py).

### scripts

These are various scripts or files used during setup or grading.

- [grader.py](./scripts/grader.py): The grading script used by `challenge.us`. Retrieves the memory address pointers dumped in `~/pointers.txt` on `exploit.us` and uses those to check the provided addresses.
    - The contents of `~/pointers.txt` are deleted after each run. That is, the user must reconnect to `exploit.us` to try again. This prevents bruteforcing the address.
- [start.py](./scripts/start.py): The start up script used by `challenge.us`. Adds the new token to `main.c` on the `challenge.us` folder and compiles it with the new token.

## Challenge Environment Initial Setup Requirements 

### Hosting the Adventure Game with xinetd

The `exploit.us` server uses `xinetd` to host the adventure game. First, install xinetd and install clang as we will need that to compile the code later.

```bash
sudo apt install xinetd clang
```

The xinetd service should be enabled by default after installation. Now create the file `/etc/xinetd.d/pwn` and add the following:

```none
service pwn
{
    disable = no
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = user
    type        = UNLISTED
    port        = 31337
    bind        = 0.0.0.0
    server      = /home/user/adventure
    log_type = FILE /home/user/pwn.log
}
```

Note that xinetd needs the `/home/user/adventure` file to exist, so despite the fact that the start up script will replace it, go ahead and place `main.c` in the home directory then compile it.

```bash
clang main.c -o adventure -g
```

That should be everything; either reboot or use `sudo service xinetd restart` to launch the game on port `31337`.

### Grading

The grading script uses python with `paramiko` to download `~/pointers.txt` from the `exploit.us` server.

```bash
pip install paramiko
```

The grading script then reads in the two lines from the file, converts them to integers by parsing them with `int(str, 16)`. The user's guesses are provided as the first and second command line arguments, which are similarly converted to integers. Converting to integers avoids potential mismatches such as case sensitivity or a leading "0x". The values are then compared with the expected values, returning success if they match.

Note that the grading script deletes the contents of `~/pointers.txt` after reading it to avoid brute-forcing the answer.

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands. 
 
```bash
history -c && history -w
```
