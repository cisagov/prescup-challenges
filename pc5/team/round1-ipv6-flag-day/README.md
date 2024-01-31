# IPv6 Flag Day

The entire ship network must be upgraded to the IPv6 routing protocol.

**NICE Work Roles**

- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0035](https://niccs.cisa.gov/workforce-development/nice-framework/): Configure and optimize network hubs, routers, and switches (e.g., higher-level protocols, tunneling).
- [T0081](https://niccs.cisa.gov/workforce-development/nice-framework/): Diagnose network connectivity problems.
- [T0121](https://niccs.cisa.gov/workforce-development/nice-framework/): Implement new system design procedures, test procedures, and quality standards.

<!-- cut -->

## Background

The current ship network uses IPv4 and consists of several networks connected by two VyOS routers. You can ping (and connect to) two different servers using their IPv4 addresses. You have administrator access to the two routers. 

Implement IPv6 SLAAC (Stateless Address Autoconfiguration) on all networks serving client or server machines and configure the two routers to forward IPv6 traffic.

## Getting Started

Below is a diagram of the ship's network topology:

```
 ------------ .7          .1 ---------------
| dmz-server |--------------| border-router |
 ------------      dmz       ---------------
               10.7.7.0/24        .1|
                                    |    lan
                                    | 10.0.0.0/30
                                    |
                                  .2|
 ------ (dhcp)            .1 ------------- .1         .3 ------------
| kali |--------------------| core-router |-------------| app-server |
 ------      competitor      -------------    devops     ------------
             10.5.5.0/24                    10.3.3.0/24
```

From your `kali` workstations: you can ping the two servers and connect to them on TCP port 31337 using `telnet` or `nc`/`ncat`.

Log into each router using `ssh` and the provided credentials. Update the existing configuration to enable IPv6 SLAAC on the `competitor`, `devops`, and `dmz` networks. 

Ensure that the `dmz-server` is reachable from your `kali` workstations by configuring IPv6 forwarding between the `core` and `border` routers.

Once IPv6 SLAAC is configured: determine the publicly routable IPv6 addresses allocated to each of the two servers; submit them to `challenge.us` via a browser on the `kali` VM; receive the tokens to submit for points.

### Hint 1:

Use any valid IPv6 routable network range(s) in your setup; however, to save time and effort consider using `2001:5::`, `2001:3::`, and `2001:7::` on the `competitor`, `devops`, and `dmz` networks, respectively.

### Hint 2:

Do not disable or replace the working IPv4 settings; you need to keep them to ensure you can connect to and configure the ship routers!

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali*      |user    |tartans |
|core-router|vyos    |vyos    |
|border-router|vyos  |vyos    |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. Enter token for app server's IPv6 address.
2. Enter token for dmz server's IPv6 address.
