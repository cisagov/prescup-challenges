# Hanging About Solution


Examining the network interface of one of the "all-purpose" (`Kali-*`)
machines on both the `mgmt` and `user` subnets, we observe that IPv6 has been
set up on both, and that SLAAC (automatic address configuration) is in effect.
We also notice that Kali Linux additionally enables the use of RFC4941
"Privacy Addressing", for a total of three IPv6 addresses configured on `eth0`:
a link-local address, a permanent global address (both based on the machine's
MAC address via EUI64), and an additional temporary (privacy) global address,
to be used by default whenever outgoing connections are initiated.

Scanning the `mgmt` network with `nmap` yields no results, which leads us to
believe that the hidden machine uses IPv6 *exclusively*.

There are several ways of using the `Kali-MGMT` workstation to
discover the IPv6-only "hidden" server:

1. Collect all MAC addresses of machines reachable via IPv4 (e.g., using
   `nmap`). Then, listen for broadcast IPv6 traffic using Wireshark, and
   identify a MAC address that's new, and not on the previously collected
   list. Once the new MAC address is identified, use an online
   [EUI-64 calculator](https://eui64-calc.princelle.org) or, locally,
   `atk6-address6 <MAC>` to obtain the hidden machine's link-local IP
   address.

2. Alternatively, ping the "All Nodes" multicast address (`ping6 ff02::1`),
   and collect all the distinct replies. Use `atk6-address6` (or match by
   watching replies in Wireshark) to recover each neighbor's MAC address,
   and select the one *not* also retrieved using an `nmap` scan of the IPv4
   address space on the `mgmt` LAN.

Once we know the link-local IPv6 address of the "hidden" server, we obtain
its permanent global IPv6 address by replacing the `fe80::` network prefix
with the global network prefix assigned to this network (which may be obtained
by examining the numbering of `eth0` on the "all-purpose" machine). In our
case, that prefix is `2001::`.

Finally, the temporary (privacy) global IPv6 address of the hidden machine
may be obtained by running `atk6-alive6 eth0` from the "all-purpose" machine
connected to the `mgmt` LAN (or, in a more labor-intensive way, by watching
multicast/broadcast packets in Wireshark).

There are a total of three IPv6 addresses that can be used to establish a
connection to the hidden server:

| Address                     | Type                                         |
|:----------------------------|:---------------------------------------------|
| `fe80::250:56ff:fe87:7ed2`  | link-local                                   |
| `2001::250:56ff:fe87:7ed2`  | global, permanent                            |
| `2001::39fd:38e4:296c:d6c8` | global, temp./privacy (may change over time) |

***NOTE***: While the temporary/privacy address may change over time *within*
a given instance of this challenge, the link-local and permanent-global ipv6
addresses will be different across different instances! While the network
prefix (`fe80::` and `2001::`, respectively) will stay the same, the *host*
portion depends on the MAC address allocated by VMWare to the hidden VM during
challenge deployment (in this case, `00:50:56:87:7e:d2`). Therefore, actual
host portions of v6 addresses are almost guaranteed to be different from the
ones noted above!

An `nmap -6 <address>` scan against either of these addresses will show that
the server is listening on TCP port `31337`. One may use `telnet` to open a
connection to all three addresses from the "all-purpose" machine on the `mgmt`
network. When contacting the link-local address, append `%eth0` as the "zone
index" to the address to clarify which interface should be used for routing
the outbound connection, like this:

```
telnet fe80::250:56ff:fe87:7ed2%eth0 31337
```

When connecting to the hidden server from a different LAN (e.g., from the
"all-purpose" machine on the `user` network), only the two global IPv6
addresses may be used.

There are a total of 5 tokens to be collected:

|   | Token        | Src. net | Dst. address              |
|---|:-------------|:---------|:--------------------------|
| 1 | `27d5ee3b77` | `mgmt`   | fe80::250:56ff:fe87:7ed2  |
| 2 | `24a102095b` | `mgmt`   | 2001::250:56ff:fe87:7ed2  |
| 3 | `2029146eb7` | `mgmt`   | 2001::39fd:38e4:296c:d6c8 |
| 4 | `8d1515aeaf` | `user`   | 2001::250:56ff:fe87:7ed2  |
| 5 | `0f891e3cce` | `user`   | 2001::39fd:38e4:296c:d6c8 |
