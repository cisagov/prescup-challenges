# Route Route Revolution

_Challenge Artifacts_

- [gradingScript.sh](./challengeserver/gradingScript.sh) -- handles the grading of the two BGP routes by performing traceroutes for each and enumerating whether the number of hops meets the supplied conditions. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [addroutes.sh](./responder/addroutes.sh) -- ensures that the two necessary static routes are in place on the responder prior to any grading attempts. This script is run at boot by a crontask under the root/sudo user. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.

_Competitor Artifacts_

Each router in the challenge consists of a VyOS version 1.4-rolling instance. You should apply the following configurations and networks to each router interface to match the config files provided.

- [router-configuration-files](./RouterConfigurationFiles/) -- includes the nine router configuration files.

- Router A:
  - eth0: abnet
  - eth1: acnet
  - eth2: aenet
  - eth3: competitor
- Router B:
  - eth0: abnet
  - eth1: bdnet
  - eth2: benet
- Router C:
  - eth0: acnet
  - eth1: cenet
  - eth2: cfnet
- Router D:
  - eth0: bdnet
  - eth1: denet
  - eth2: dgnet
  - eth3: dlnet
- Router E:
  - eth0: aenet
  - eth1: benet
  - eth2: cenet
  - eth3: denet
  - eth4: efnet
  - eth5: egnet
  - eth6: ehnet
  - eth7: einet
- Router F:
  - eth0: cfnet
  - eth1: efnet
  - eth2: fhnet
  - eth3: fmnet
- Router G:
  - eth0: dgnet
  - eth1: egnet
  - eth2: ginet
- Router H:
  - eth0: ehnet
  - eth1: fhnet
  - eth2: hinet
- Router I:
  - eth0: einet
  - eth1: ginet
  - eth2: hinet
  - eth3: iknet

The responder and challenge server stand in can be configured with the following networks and IPv6 addresses.
- Responder system:
  - eth0: fmnet | 2001:0db8:abcd:4444::1000
  - eth1: iknet | 2001:0db8:abcd:2222::1000

- Challenge Server:
  - eth0: competitor | 2001:0db8:acbd:1111::1000
  - eth1: can be anything
  - eth2: dlnet | 2001:0db8:abcd:3333::1000
