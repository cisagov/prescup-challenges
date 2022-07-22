# Setup instructions for "Hanging About" challenge

## Network Map

The challenge requires three Linux VMs, two of which (`Kali-*`) should be
accessible to competitors, networked together like so:

```
-------------
| Kali-USER |
------+------
      |
  ----+-----------+----- user LAN
                  |
         ---------+---------
         | router/firewall |
         ---------+---------
                  |
  ----+-----------+-----+---- datacenter mgmt. LAN
      |                 | 
------+------      -----+---------------------
| Kali-MGMT |      | Hidden ipv6-only Server |
-------------      ---------------------------
                      fe80::250:56ff:fe87:7ed2 (link-local)
                      2001::250:56ff:fe87:7ed2 (global perm.)
                     2001::39fd:38e4:296c:d6c8 (global temp.)
```

The hidden datacenter machine communicates only using IPv6. The user
accessible Kali machines are dual-stacked.

***NOTE*** The common (host-specific) portion of the link-local and
permanent global IPv6 address is derived from the network interface's
ethernet MAC address, and will therefore be different on a new deployment!

## Hidden server configuration

Ensure that privacy IPv6 addresses are enabled on the datacenter network
interface. Assuming the interface is `eth0`, type:

```
echo 2 > /proc/sys/net/ipv6/conf/eth0/use_tempaddr
```

Run (or set up a service to automatically start at boot) the included
grading script (`./server/flagger.sh`):

```
/usr/bin/ncat -l -k --no-shutdown -c /path/to/flagger.sh
```

This script will return tokens based on the origin of a connecting
(`ncat` or `telnet`) TCP client.
