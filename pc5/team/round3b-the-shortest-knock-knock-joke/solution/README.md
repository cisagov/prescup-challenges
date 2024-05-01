# The Shortest Knock-Knock Joke

*Solution Guide*

## Overview

*Knock-Knock* asks players to find a server on the network using port knocking and Nmap. Then, send data to receive the token.

## Question 1

*Connect the server on the correct open port and send any string. You will receive the token.*

In a terminal, use Nmap to scan the IP range: `10.200.200.0/24`.

```bash
nmap -sP 10.200.200.0/24
```

Use Nmap again to find open port `31337` on the server that is *not* `10.200.200.5`.

```bash
nmap -sC -sV 10.200.200.*
```
If you use `nmap` you will get the token. If you miss it, or do not get it for some reason, you can use `telnet` or Netcat (`nc`) too.

```bash
telnet 10.200.200.* 31337
```
