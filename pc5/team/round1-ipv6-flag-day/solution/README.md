# IPv6 Flag Day
_Solution Guide_

## Overview

This challenge requires competitors to configure two VyOS routers to add IPv6 Stateless Address Autoconfiguration (SLAAC) and routing support.

The existing network is already IPv4. Two servers must be made reachable over IPv6:

- `app-server`: on a network directly connected to the same router as competitors' `kali` workstations, and 
- `dmz-server`: on a network that's one routing hop away hosted by a neighboring router

Competitors must deduce the IPv6 address allocated to each server and submit them for grading to `http://challenge.us` in exchange for the tokens to be submitted for credit.

## Question 1

*Enter token for app server's IPv6 address*

The `app-server` is located on the `devops` network, which is served from the same `core-router` as the `competitor` network connecting your `kali`workstation. The `devops` network uses IPv4 addresses in the `10.3.3.0/24` range; specifically, the `app-server` itself is at IPv4 address `10.3.3.3`. 

If you connect to its TCP port 31337 using `nc`:

```bash
$ echo | nc 10.3.3.3 31337
```

you will receive the following message:

```bash
You are connecting from 10.5.5.X over ipv4
```

To enable connecting to this machine over IPv6: enable IPv6 SLAAC on both the `competitor` and `devops` subnets by connecting to and configuring the `core-router`. 

```bash
$ ssh vyos@10.3.3.1
[...]
configure
set interface ethernet eth1 ipv6 address autoconf
set interface ethernet eth2 ipv6 address autoconf
set service router-advert interface eth1 prefix 2001:5::/64
set service router-advert interface eth2 prefix 2001:3::/64
commit
save
exit
```

Notice we are using `2001:5::/64` as the IPv6 network range for `competitor`, and `2001:3::/64` for `devops`. Because the ship network is completely sandboxed, any otherwise valid routable IPv6 address range should work.

Since we do not have credentials to log into `app-server` (over IPv4) and query its interface for the auto-configured IPv6 address, we'll have to find another way to obtain that address. We can do that by querying the "all-hosts" IPv6 multicast address on the `core-router`'s `devops` (i.e., `eth2`) interface:

```bash
$ ping6 ff02::1%eth2
```

This results in output that looks like:

```bash
64 bytes from fe80::250:56ff:feb6:a0ac%eth2: icmp seq 1 ttl 64 time=0.035ms
64 bytes from fe80::250:56ff:feb6:4174%eth2: icmp seq 1 ttl 64 time=0.043ms
...
```

...showing replies from all hosts connected to that network. We must now rule out the `core-router`'s own IPv6 address on `eth2`:

```bash
ip -6 address show dev eth2
3: eth2: <...> ...
   inet6 2001:3::250:56ff:feb6:a0ac/64 scope global dynamic mngtmpaddr
      ...
   inet6 fe80::250:56ff:feb6:a0ac/64 scope link
      ...
```

Notice how the *host* portion of both global and link-local addresses contain `::250:56ff:feb6:a0ac`. This means the *host* portion of the global IPv6 address belonging to `app-server` will match `::250:56ff:feb6:4174`.

Therefore, the globally routable IPv6 address of the `app-server`, and the answer to the first question, is `2001:3::250:56ff:feb6:4174`.

### Submission Note

The *actual* answer (and, therefore, the correct submission) depends on the network prefix (`2001:3::`) selected for `devops`, and on the (randomly allocated) MAC address of the `app-server` machine's interface, from which SLAAC IPv6 addresses are automatically derived!

## Question 2

*Enter token for dmz server's IPv6 address*

The `dmz-server` is located on the `dmz` network, directly connected to the `border-router`. It is ***not*** directly connected to the same router serving the `kali` workstations and the `competitor` network. To make this machine reachable over IPv6, we have to enable SLAAC on the `dmz` subnet, and also configure the two routers (`core` and `border`) to forward each other's traffic as needed. This could be accomplished by programming in static default routes on each router pointing at the other. However, a more generic and elegant solution is to enable a dynamic IPv6 routing protocol such as OSPFv3 (Open Shortest Path First). This solution is illustrated below.

On the `core-router`, let's enable OSPFv3 on the interface facing `border-router`:

```bash
$ ssh vyos@10.3.3.1
[...]
configure
set protocols ospfv3 area 0 interface eth0
set protocols ospfv3 parameters router-id 10.0.0.2
set protocols ospfv3 redistribute connected
commit
save
exit
```

On the `border-router`, enable SLAAC on the `dmz` facing interface (`eth1`), and OSPFv3 on the `core` facing interface (`eth0`):

```bash
$ ssh vyos@10.0.0.1
[...]
configure
set interface ethernet eth1 ipv6 address autoconf
set service router-advert interface eth1 prefix 2001:7::/64
set protocols ospfv3 area 0 interface eth0
set protocols ospfv3 parameters router-id 10.0.0.1
set protocols ospfv3 redistribute connected
commit
save
exit
```

At this point, both routers share reachability information about their directly-connected networks with each other over the OSPFv3 link. Therefore, when the IPv6 address of the `dmz-server` machine is used in `ping`, `telnet`, or `nc` from `kali`, the traffic is correctly forwarded across the link between the two routers.

Follow the same procedure used in Question 1 above to learn the automatically allocated IPv6 global address for the `dmz-server` (while logged into the `border-router`).

Submit the global address as the answer to the second question.

### Submission Note

The *actual* answer (and, therefore, the correct submission) depends on the network prefix (`2001:7::`) selected for `dmz`, and on the (randomly allocated) MAC address of the `dmz-server` machine's interface, from which SLAAC IPv6 addresses are automatically derived!
