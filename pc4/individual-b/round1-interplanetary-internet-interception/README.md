# Interplanetary Internet Interception

Find the Default Gateway, Intercept/Decrypt TLS Traffic, and Analyze the Spaceship's HTTP(S) queries/responses.

**NICE Work Roles**

- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-operator)

**NICE Tasks**

- [T0567](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0567) - Analyze target operational architecture for ways to gain access.
- [T0643](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0643) - Deploy tools to a target and utilize them once deployed (e.g., backdoors, sniffers)

## Background

The Dauntless spaceship has a system that queries a remote HTTPS web server for mission instructions. Every ~60 seconds, the mission workstation queries the ground station mission web server regarding all possible missions. At any time only one mission is the correct/current mission while the others are not selected (incorrect). Nobody can find the physical mission workstation onboard the spaceship; however, you have your Kali machine plugged in to the appropriate default gateway/router. It is your task to find the default gateway (router), intercept/decrypt the HTTPS requests, and find the current mission!

## Topology

![c16-topology-2096647116.png](https://launchpad.cisa.gov/tm/docs/521cf788687c4032abaa5829069563c2/c16-topology-2096647116.png)

## Getting Started

The individual that set up this network remembers that he set a firewall rule that only allowed one specific IP address in the 172.17.6.0/24 subnet to ssh into the default gateway/router. This individual also remembers that the mission workstation accepts any X.509 certificates (including self-signed).

- Task 1: Find the correct 172.17.6.0/24 IP address that will allow you to access SSH on the default gateway/router.
- Task 2: Log in to the default gateway/router and intercept the HTTPS requests (PolarProxy and sslsplit are attached to Kali's CD Drive).
- Task 3: Analyze the intercepted/decrypted HTTPS requests and answer the questions below.

## Challenge Questions

1. What is the only IP address that the default gateway (router) will accept SSH connections from on your subnet?
2. What is the ID of the correct mission name in the HTTPS traffic?
