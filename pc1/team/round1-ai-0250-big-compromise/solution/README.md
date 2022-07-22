<img src="../../../pc1-logo.png" height="250px">

# Big Compromise

## Solution

1. By viewing the web proxy log, you should observe the internal IP `172.16.80.54` downloaded `silkagent.exe` from
`46.236.64.10`. Two other files were downloaded from `46.236.64.15`, however `silkagent.exe` was the first executable.
2. `172.16.80.54`
3. The web proxy log identifies `46.236.64.0/24` as a potentially bad IP block, and this can be corroborated with
firewall log analysis. Both internal hosts `172.168.80.54` and `172.16.90.11` require follow-up investigations as each
is observed downloading files from this questionable source. `172.16.90.11` can also be observed accessing a web page
hosted on `56.34.125.200`.
4. Within `fw1-log.csv`, you should see `172.17.40.11` (the transaction server) is connected to `46.236.64.10` on TCP
port 443. This remote IP has been identified as a potential threat from previous analysis. `172.17.40.11` has additional
connections with an external host, `54.239.17.6`, which may also require further investigation.
5. Although there are inbound connections from `54.239.17.6`, the question asks for more information on outbound
connections. The TCP port that `46.236.64.10` is listening on is `443`. This is observed in `fw1-log.csv`.
6. Within `fw2-log.csv` you should see a number of connections involving `172.17.40.11`.  These include connections with
a router, domain controller, monitoring server, and the syslog server. Only one connection is with a user machine,
`172.16.80.54`. The destination TCP port on `172.17.40.11` is `445`, a common port for both Windows administration and
exploits.
7. According to `fw3-log.csv`, `172.16.90.11` is using ping (ICMP) and web-browsing (presumably HTTP) to connect to
`56.34.125.200` and ssl to connect to `56.34.125.100`.
8. `hping2-rc3-win32.zip` was observed in the web proxy log. HPing is a tool that can be used for packet generation,
including ICMP data exfiltration and/or covert communications.
9. `WKST011`. Importing the Splunk data file into Excel could make searching this file easier. However, importing large
datasets similar to this raw Splunk file may be problematic. Tools like `find` and `grep` are useful for parsing large
files, but you must have a good idea of what you are searching for. Queries for `172.16.90.11` will highlight several
Windows events from that host, and when combined with `4624` (the event ID for Successful Logon), the number of lines to
review becomes manageable.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
