<img src="../../../logo.png" height="250px">

# Instructions

Select which firewall ruleset file meets all of the conditions below (there will be only one). The filename of this
ruleset file will equal your flag for submission (i.e. Ruleset-at3hi78d56pn).

## Conditions

1. Only MGMT workstations can ping the DMZ and the Internet
2. Web traffic over HTTPS and DNS traffic are only allowed outbound to the Internet from the MGMT Workstations and Users
within the LAN. The Services network should be denied outbound unless otherwise stated below.
3. DMZ Web traffic (HTTP or HTTPS) is allowed to any internal (LAN) system and vice versa.
4. DMZ Web (HTTP or HTTPS) and DNS traffic is allowed to any external host on the Internet in order to support customer
use.
5. DMZ Web server must be able to connect over port 5889 to the Transaction Server at 10.0.20.30 in the Services subnet.
6. Email traffic over SMTP is allowed to/from the Email Server only.
7. The Log Server is allowed to connect to an Internet cloud storage server at 27.18.160.120 over port 443 and vice
versa.
8. Deny everything else.

## Assumptions

For this challenge, the OPT interface on the firewall associates with the DMZ. You can safely assume that there are no
other devices or networks in the LAN other than what is displayed in the network map image. You can also assume that
there are no other rules or ACLs being implemented by other devices within the network, besides this lone firewall.
Prioritize functionality over realism. This is only a simulated scenario and is not intended to portray the best, most
efficient, or only firewall rule set able to achieve the end goal. Any and all intentional inaccuracies should be fairly
obvious.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
