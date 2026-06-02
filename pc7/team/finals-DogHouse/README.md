# DogHouse

You are tasked with compromising a PLC device deep within the target network. To do so you must move through multiple different systems, avoiding network defenses and taking advantage of Kerberos configurations.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework/)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework/)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework/): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework/): Identify vulnerabilities

## Background

Your spy agency has been keeping tabs on APT X for some time. You were able to gather intel on an expensive deal made between APT X and Cloud Tech Foundry (CTF), an offsite cloud hosting provider. APT X is using CTF's servers to host much of their critical infrastructure. You are tasked with breaking into CTF's network and damaging their servers, inflicting a significant blow on APT X's operations and finances.

## Getting Started

Use the provided `kali` machine to access the CTF `web` device and hack your way into the network from there.

## Tokens

- Token 1: Service requests on the CTF `web` page are downloaded and clicked on by `ubuntu1` behind the web proxy. The first token is in the `/tmp` directory on `ubuntu1`.
    - The `squid` proxy allows outbound traffic only on port `443` and `8443` over TLS.
    - `ubuntu1` scans uploads with an AV. Well-known payloads are deleted, proceed with caution.
- Token 2: Exploit the `web-internal` web server to elevate your access rights. Advance deeper into the network to reach this server.
- Token 3: Take advantage of the `ca` and Kerberos `pkinit` to escalate to `admin` privileges, and find the token on `client1`.
- Token 4: Send Modbus data to the `plc` that controls the water tank in order to flood the server room.
    - Make sure you fill the water tank to maximum capacity before draining it.
    - The `plc` is listening on port `5020`.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|password|
