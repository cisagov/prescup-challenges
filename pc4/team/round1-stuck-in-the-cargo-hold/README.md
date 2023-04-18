# Stuck in the Cargo Hold

After the Dauntless experienced a mysterious power surge, your team ends up split, and stuck in two of the ship's cargo storage rooms. The door switches are not operational, so you'll need to use the computer terminals available in each hold to connect to the ship's SCADA server and actuate the doors from there. However, the IPv6 routing configuration of the ship's backbone network seems to also have been reset to factory defaults...

**NICE Work Roles:**
- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/workroles?name=Network+Operations+Specialist&id=All)

**NICE Tasks:**
- [T0035](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0035&description=All) - Configure and optimize network hubs, routers, and switches.
- [T0081](https://niccs.cisa.gov/workforce-development/cyber-security-workforce-framework/tasks?id=T0081&description=All) - Diagnose network connectivity problems.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this
challenge in the hosted environment.

## Background

There are a total of four terminals directly accessible by team members, two of which are located in each cargo hold area.

The ship backbone network is supported by three routers, all of which have `ssh` service enabled as part of their "factory default" configuration.
Run `prescup-get-token` after logging into each router for flags that count toward partial credit for the challenge.

Finally, the SCADA server is located in the ship datacenter, and will yield the final two flags that open each cargo hold door if a connection
to its TCP port 31337 is opened from one of the four cargo hold terminals (using `telnet`, `nc`, or `ncat`). The server will only respond to accesses
made from the IPv6 address ranges associated with the cargo hold terminals.

The relevant network map is shown below:

```
   cargo hold 1
   (2001:1::/64)
         |
 -----   |   -----------
| K11 |--|  |      R1   |
 -----   |  |           |
 -----   |--|e0         |   -----------
| K12 |--|  |    e1   e2|--|e1         |   data center
 -----   |   -----+-----   |           |   ----
                  | OSPFv3 |  R3     e0|--| S1 |
 -----   |   -----+-----   |           |   ----
| K21 |--|  |    e1   e2|--|e2         |   (2001:3::/64)
 -----   |  |           |   -----------
 -----   |--|e0         |
| K22 |--|  |      R2   |
 -----   |   -----------
         |
   (2001:2::/64)
   cargo hold 2
```

## Getting Started

Your team only has direct access to the four terminals: `K11`, `K12` (in cargo hold 1), and `K21`, `K22` (in cargo hold 2). From there, find a way to ssh into `R1`, `R2`, and `R3`, and configure all three to restore IPv6 routing and addressing for the three access networks in cargo holds 1 and 2, and the data center.

Finally, determine the address of the SCADA server `S1` and open connections to it over TCP port 31337 from terminals in both cargo hold areas to obtain the final two flags.

## Submission Format

Each flag is formatted as an 8-digit hexadecimal string.

Flags for `R1` and `R2` are each worth 5% of the total; the `R3` flag is
worth 10%; finally, each "cargo hold door flag" from the SCADA server `S1`
is worth 40% of the total points for this challenge.

## Challenge Questions

1. Router r1 flag (output of `prescup-get-token` command on r1)  
2. Router r2 flag (output of `prescup-get-token` command on r2)  
3. Router r3 flag (output of `prescup-get-token` command on r3)  
4. Server s1 flag from cargo hold 1 (output of `telnet` to s1's tcp port 31337 from the 2001:1::/64 subnet)  
5. Server s1 flag from cargo hold 2 (output of `telnet` to s1's tcp port 31337 from the 2001:2::/64 subnet)
