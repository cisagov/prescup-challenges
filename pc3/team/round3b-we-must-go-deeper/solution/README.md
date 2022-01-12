# We Must Go Deeper Solution

A list of six suspects' ISPs have produced netflow data collected at the
router interface serving each respective suspect's LAN. Each of up to six
team members should grab one such netflow collection (`NA`, `EU`, `AS`,
`OC`, `AF`, and `SA`, respectively), and focus on traffic involving the
targeted suspect's IP address:

| handler | IP address     |
| ------- | -------------- |
|    NA   | 128.237.119.12 |
|    EU   |    2.69.27.123 |
|    AS   |  1.235.189.106 |
|    OC   |  58.172.47.117 |
|    AF   |   45.104.34.74 |
|    SA   |  152.200.19.77 |

Begin by unpacking the provided netflow data:

```
tar xvfJ challenge/netflow.tar.xz
cd netflow
```

## 1. Identifying Communication Relays

Using `AF` and `45.104.34.74` as an example, we start by listing all flows
involving the latter:

```
nfdump -R ./netflow_af 'host 45.104.34.74'
```

The overwhelming majority of the flows involve TCP port 80 on `45.104.34.74`,
which is consistent with it being a "handler" receiving reports from a large
number of "field agents" as determined during an earlier challenge.

Focusing on port 80, we list the top 20 source and destination IP addresses
communicating with `45.104.34.74` over port 80:

```
nfdump -R ./netflow_af 'host 45.104.34.74 and port 80' -s srcip -s dstip -n 20
```

We notice that all such hosts tend to have the same "profile": single
conversation whereby the remote client sends approximately 1000 bytes to
`45.104.34.74`'s TCP port 80, and receives a 409 byte response. Therefore,
we conclude that all relevant TCP port 80 traffic consists of "field agents"
checking in with their handler.

We then proceed to look at traffic ***not*** involving TCP port 80:

```
nfdump -R ./netflow_af 'host 45.104.34.74 and not port 80' -s srcip -n 20
```

This yields three IP addresses: `62.143.73.187`, `27.242.37.2`, and
`128.237.119.24`. After some further probing, these machines all communicate
with our suspect, `45.104.34.74` over TCP port 22 (SSH), as both clients and
as servers. This fits the idea that these machines are acting as some sort of
communication *relays* between our suspected "handler" and some other machines.

## 2. Identifying Moon Base (Leadership) Addresses

Based on the observation that one of the communication relays we identified
(`128.237.119.24`) shares a subnet with our suspected `NA` handler
(`128.237.119.12`), we focus our subsequent efforts on the `netflow_na` folder
produced by the `NA` ISP:

```
nfdump -R ./netflow_na 'host 128.237.119.24 and port 22' -s dstip -n 20
```

We obtain a list of eight IP addresses, which includes five of the six
suspected handlers (not including `128.237.119.12`, since communications
between hosts on the local LAN would not be picked up by netflow), and an
additional three addresses: `44.106.35.11`, `44.2.22.75`, and `44.91.84.131`,
which must be the addresses used by the alien's Moon Base Leadership.

Communication between handlers and leadership occurs by contacting one of
the three relays over SSH, which then reaches out to all other handlers and
leaders on the Moon Base to relay each individual message.

Submitting the IP addresses of the three relays and the three Moon Base
machines (for a total of 6 IP addresses) should result in full credit being
awarded for this challenge.
