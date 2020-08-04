<img src="../../../logo.png" height="250px">

# Breaking All The Rulez

## Solution

The correct choice for the version in this repository is `Ruleset-86evewzu0sas`.

### Misconfigurations

The other 9 files will have one of the following things wrong/broken:

1. Wrong port in DMZ to Transaction DB rule (port reads 5998 instead of 5889)
2. HTTP or HTTPS rule changed to blocked at the WAN interface instead of allowed
3. LAN Deny All rule at higher position which nullifies following rules
4. Allow all placed at the top for the LAN interface
5. Port/service of the Log Backup element is incorrect (HTTP instead of HTTPS)
6. SMTP goes to IP address of the DC instead of the Email Server
7. DMZ Web and DNS IP’s reversed
8. All LAN systems allowed to Internet over HTTPS instead of just MGMT workstations and Users
9. ICMP allowed inbound to everything instead of just MGMT Workstations

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
