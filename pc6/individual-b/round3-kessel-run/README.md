# Kessel Run

You are the legendary smuggler, Scan Solo. 
You're reworking the HTTP (Hyperspace Tunnel Transfer Protocol) drive in the Millennium Packet and believe you can make the Kessel Run in only 3 proxsecs (1 proxsec = 1 proxy hop).

Can you pull off this impossible HTTP smuggling through the volatile Hackadese Maelstrom surrounding Kessel?

**NICE Work Roles**

- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Secure Software Development](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1091](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform authorized penetration testing on enterprise network assets.
- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify vulnerabilities.
- [T1262](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify programming code flaws.

## Background

Use the provided Kali machine to craft a "single" HTTP request to bypass three different proxies to reach `kessel.us`. You'll need to smuggle your way through `channel.us`, `maelstrom.us`, and `maw.us` to finally reach `kessel.us`. 

## Getting Started

The following image demonstrates your path to reach Kessel. Each proxy server has three paths available, one named after itself, one named `/token`, and one named after the next proxy in the chain (requests to this path are forwarded to that next proxy). Each server is running on port `8080`. If needed, the image can also be downloaded from `challenge.us/files` from your Kali machine. 

![A simple network diagram showing 4 hosts: channel.us, maelstrom.us, maw.us, and kessel.us. There is an arrow pointing from channel to maelstrom (labelled /maelstrom), maelstrom to maw (labelled /maw), and maw to kessel (labelled /kessel), representing each of the proxy hops.](challenge/artifacts/KesselRun.png "Network Diagram for 'Kessel Run'")

You can download a copy of the proxies and a script to run them from `challenge.us/files`. The provided `run.sh` script runs the proxies on `localhost` with `channel.us` on 8080, `maelstrom.us` on 8081, `maw.us` on 8082, and `kessel.us` on 8083. The `run.sh` command otherwise runs the proxies as described above, logging output to `stdout` and `{proxy_name}.log` files matching each of the proxies.  

## Submission

There are 3 tokens to retrieve in this challenge. Each token is a 12-character hexadecimal value.

- Token 1: Retrieve the token found at `/token` on `maelstrom.us` after passing through `channel.us`.
- Token 2: Retrieve the token found at `/token` on `maw.us` after passing through `maelstrom.us`.
- Token 3: Retrieve the token found at `/token` on `kessel.us` after passing through `maw.us`.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-kessel|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.