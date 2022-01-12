# Dunning & Kruger Netflow, Inc. Solution

### Once again, the list of questions being asked:

1. What is the attackers' (external) IP address?
2. What is the legitimate administrator's (external) IP address?
3. What is the IP (on the datacenter network) and port number of the D&K database server?
4. When does the Hydra SSH brute-force attack (incl. initial SYN scans of tcp/22) start and end?
5. What is the duration of the longest successful TCP attacker-initiated session between the compromised D&K user-LAN IP and the D&K datacenter machine?


## Solution

After studying the `nfdump` manual for a while, we decide to aggregate flows
bi-directionally (`-b`), and sort entries by the timestamp of the first packet
in the bi-directional conversation (`-O tstart`). The output looks somewhat
like this (slightly annotated to reduce horizontal width):

```
First seen  Duration Proto  Src IP Addr:Port   Dst IP Addr:Port  Opkt  Ipkt
11:10:36.997   0.000 ICMP  168.192.0.10:0 <->    12.0.0.54:0.0      0     1
11:10:36.997   0.000 ICMP     12.0.0.54:0 <-> 168.192.0.10:8.0      0     1
11:10:37.549   0.000 ICMP     12.0.0.54:0 <-> 168.192.0.20:8.0      0     1
11:10:37.549   0.000 ICMP  168.192.0.20:0 <->    12.0.0.54:0.0      0     1
11:10:37.747   0.000 ICMP     12.0.0.54:0 <-> 168.192.0.30:8.0      0     1
11:10:37.747   0.000 ICMP  168.192.0.30:0 <->    12.0.0.54:0.0      0     1
11:10:37.824   1.416 ICMP     12.0.0.54:0 <-> 168.192.0.40:8.0      0     2
11:10:37.824   1.416 ICMP  168.192.0.40:0 <->    12.0.0.54:0.0      0     2
11:10:40.060  13.157 ICMP  168.192.0.50:0 <->    12.0.0.54:0.0      0     7
11:10:40.060  13.157 ICMP     12.0.0.54:0 <-> 168.192.0.50:8.0      0     7
```

The above fragment shows that an external IP address (`12.0.0.54`) is pinging
addresses on D&K's user network (`168.192.0.0/24`), with the likely intent of
gathering a list of machines for further probing. The pinging starts at time
`11:10:36.997` (first flow), and ends `13.157` seconds after the start of the
last ICMP flow (at `11:10:40.060 + 13.157 = 11:10:53.217`).

Next in the chronological sequence of events we find this set of flows:

```
First seen      Dur Prot  Src IP Addr:Port      Dst IP Addr:Port  Opkt  Ipkt
11:10:45.443 47.046 TCP  168.192.0.10:22   <->    12.0.0.46:35534  224   123
11:11:05.597  0.007 TCP  192.168.0.10:5432 <-> 168.192.0.10:35200    8     6
11:11:08.364 21.043 TCP  192.168.0.10:5432 <-> 168.192.0.10:35202   17    13
```

An SSH session lasting approximately 47 seconds, from an external IP address
(`12.0.0.46`) that is *different* from that of the presumptive attacker from
before, overlaps with the destination machine on the D&K user network
(`168.192.0.10`) issuing a connection to the database server on the PostgreSQL
port (`192.168.0.10:5432`). This is consistent with a legitimate administrator
who is known to have remotely logged into the database "at around the same
time the attack was reported".

Meanwhile, our attacker (`12.0.0.54`) is generating a lot of activity:

```
First seen  Duration Proto  Src IP Addr:Port   Dst IP Addr:Port  Opkt  Ipkt
11:11:11.415   0.136 TCP   168.192.0.10:22  <->  12.0.0.54:48413    2     1
11:11:11.420   0.137 TCP   168.192.0.40:22  <->  12.0.0.54:48413    2     1
11:11:11.420   0.137 TCP   168.192.0.20:22  <->  12.0.0.54:48413    2     1
11:11:11.420   0.137 TCP   168.192.0.30:22  <->  12.0.0.54:48413    2     1
11:11:11.420   0.137 TCP   168.192.0.50:22  <->  12.0.0.54:48413    2     1
```

The attacker is using the same source port to probe TCP port 22 on the
machines it was presumably able to ping during the earlier ICMP scan, and
determining whether any of them are listening for inbound SSH connections.

Next, we have a large sequence of somewhat lengthier SSH connections:

```
First seen  Duration Proto  Src IP Addr:Port   Dst IP Addr:Port  Opkt  Ipkt
11:11:21.657   1.145 TCP   168.192.0.10:22  <->  12.0.0.54:52576   14    13
11:11:22.669   1.154 TCP   168.192.0.20:22  <->  12.0.0.54:35162   14    13
11:11:23.684   1.153 TCP   168.192.0.30:22  <->  12.0.0.54:53932   14    13
...
11:14:59.482   1.327 TCP   168.192.0.10:22  <->  12.0.0.54:53682   15    14
11:14:59.497   1.181 TCP   168.192.0.20:22  <->  12.0.0.54:36268   13    12
11:14:59.513   1.161 TCP   168.192.0.10:22  <->  12.0.0.54:53686   13    12
```

All of this is part of  the attacker running `hydra` to attempt a brute-force
enumeration of users and passwords found likely to work on machines operated by
careless users and/or administrators.

Once the brute-force attack is successful, the attacker actually connects to
the victim machine, for a relatively lengthy session that subsumes all further
activity generated from the compromised machine:

```
First seen  Duration Proto  Src IP Addr:Port   Dst IP Addr:Port  Opkt  Ipkt
11:15:14.634 113.320 TCP   168.192.0.10:22  <->  12.0.0.54:53688  626   353
```

Since all further port scanning and database connectivity to the D&K datacenter
network occurs within this time window (starting after `11:15:14.634` and
concluding before `11:15:14.634 + 113.320 = 11:17:07.954`), we can safely
assume all that activity is also directly attributable to the attacker.

The remaining steps are addressed similarly to the above, utilizing the
compromised D&K user-LAN machine (`168.192.0.10`) as the new source of any
attacks.

The first thing we notice immediately after the user machine's compromise,
is that it starts generating a large amount of tcp requests to ports 80
and 443 of a wide range of IP addresses on the D&K datacenter network
(`192.168.0.0/24`). Adding `-o long` to the `nfdump` command line, we get:

```
First seen  Duration Proto  Src IP Addr:Port     Dst IP Addr:Port  Flags Pkt
11:15:31.954   0.000 TCP   168.192.0.10:42086 -> 192.168.0.9:80 ......S.   1
11:15:31.954   0.000 TCP   168.192.0.10:42124 -> 192.168.0.7:80 ......S.   1
11:15:31.954   0.000 TCP   168.192.0.10:45734 -> 192.168.0.4:80 ......S.   1
```

which is consistent with a TCP SYN based "ping scan" of the subnet, as used
with e.g., the `nmap -sn` or `nmap -sP` commands.

The remaining steps are skipped, as the techniques for finding the answers
have already been covered above.

## Answer Key

| Q | A                           |
|---|-----------------------------|
| 1 | `12.0.0.54`                 |
| 2 | `12.0.0.46`                 |
| 3 | `192.168.0.10:5432`         |
| 4 | `11:11:11.415,11:15:00.674` |
| 5 | `19.468`                    |
