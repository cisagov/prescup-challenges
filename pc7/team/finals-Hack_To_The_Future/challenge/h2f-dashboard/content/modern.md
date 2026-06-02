# Time Bandwidths

A wealthy, but eccentric businessman is convinced that he can capture signals sent by time travelers from alternate timelines.
Whether his theories hold any merit or not is none of your concern.
Your mission is to use his server as an injection point for your own backdoor.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities

## Background

It is the present year.
You are tasked with breaking into the network of a wealthy businessman.
This businessman believes that it is possible to pick up digital signals sent from alternate timelines.
He has set up a server that listens for traffic on port `8888`.
This server will prove to be our method of persistence.
You must access the network with captured ssh credentials and then inject a bind shell into the server's memory.
Be sure to keep the server intact so as not to raise suspicions. 

## Getting Started

Access `ubuntu.mod.pccc` via ssh, using `user:password` for login.
`ubuntu.mod.pccc` is running a process called `server` listening on port `8888`.

You need to inject shellcode into the running `server` process.
The shellcode must open a bind shell on port `8080`.
The shellcode must be capable of accepting a ncat connection from `grader.mod.pccc`.
Make sure you preserve the functionality of the `server` process.
You must inject raw shellcode into memory, loading shared objects or libraries is not allowed.

If you crash the server, or disable its intended functionality, the grader will not give you the token.
The full path to the server binary is `/time-bandwidths/server`.
In the event you do crash the server, simply restart it: `cd /time-bandwidths; /time-bandwidths/server &`. 
Please note: the server must be run from within the `/time-bandwidths/` directory (you must `cd` to `/time-bandwidths` before executing the server). 
The server is a simple http server that serves the file `welcome.txt`, which displays a welcome message to time travelers.
You can access the server at `http://ubuntu.mod.pccc:8888/welcome.txt`.

When you have injected your shellcode, and it's ready to be connected to, run the grader at `http://grader.mod.pccc`.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|password|
|ubuntu.mod.pccc|user|password|