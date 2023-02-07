# Stuck in the Cargo Hold

_Solution Guide_

## Overview

_Stuck in the Cargo Hold_ is an infinity-style challenge. Notice that this solution guide is organized a little differently than other solution guides you may have read.

## Question 1

_Router r1 flag (output of `prescup-get-token` command on r1)_ 

## Question 2

_Router r2 flag (output of `prescup-get-token` command on r2)_  

## Connecting to `R1` and `R2`

1. Ping the `all-routers` multicast address to find the `R1` and `R2` link-local address from `K1*` and `K2*` terminals, respectively:
   `ping ff02::2%eth0`
2. SSH into the router (username and password are both `vyos`):
    `ssh vyos@<link-local-ipv6-address>%eth0`
3. Collect token for `R1` and, respectively, `R2`: 
   `prescup-get-token`

## Question 3

_Router r3 flag (output of `prescup-get-token` command on r3)_  

1. View router configuration:
   `show config`
2. Restore missing configuration. For example, the following would work for `R1` (use a similar set of configuration commands on `R2`):

```
conf
set system host-name r1
set service router-advert interface eth0 prefix 2001:1::/64
set protocols ospfv3 area 0 interface eth1
set protocols ospfv3 area 0 interface eth2
set protocols ospfv3 parameters router-id 192.168.1.1
set protocols ospfv3 redistribute connected
commit
save
exit
```

   After this, cargo hold terminals should have automatically acquired routable IPv6 addresses in the `2001:1::/64` and, respectively, `2001:2::/64` address ranges.

3. Find link-local address for router `R3` (from either `R1` or `R2`):
   `ping6 ff02::2%eth2`

## Connecting to `R3`

1. From either `R1` or `R2`, SSH into address obtained in the previous step  (once again, both username and password are `vyos`):
   `ssh vyos@<nexthop-link-local-ipv6-address>%eth2`

2. Collect token for `R3`: 
   `prescup-get-token`


## Question 4

_Server s1 flag from cargo hold 1 (output of `telnet` to s1's tcp port 31337 from the 2001:1::/64 subnet)_

1. View router configuration:
   `show config`

2. Restore missing configuration:

```
conf
set system host-name r3
set service router-advert interface eth0 prefix 2001:3::/64
set protocols ospfv3 area 0 interface eth1
set protocols ospfv3 area 0 interface eth2
set protocols ospfv3 parameters router-id 192.168.1.3
set protocols ospfv3 redistribute connected
commit
save
exit
```

3. Determine the IPv6 address of SCADA server `S1` (while still on `R3`):
   `ping ff02::1%eth0`

​     This will provide the *link-local* address of the server `S1`. Use the  host portion (least significant 64 bits) in conjunction with the routable  network address configured on `R3` for the datacenter subnet (`2001:3::/64`)  to connect to `S1` from the cargo hold terminals.

## Question 5

_Server s1 flag from cargo hold 2 (output of `telnet` to s1's tcp port 31337 from the 2001:2::/64 subnet)_

## Connecting to the server to obtain the final token

At this point, connectivity between the `K**` cargo hold terminals and the server at `2001:3::*` should have been restored. To obtain the final pair of flags, do the following (from each of the two cargo hold networks, respectively):

`telnet 2001:3::<host-address-portion-from-link-local> 31337`
