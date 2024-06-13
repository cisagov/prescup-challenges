# Dead Beef Drop

A vulnerable network service is protected by a NAT+Firewall gateway--its purpose is to prevent known bad requests from reaching the server. Complete the gateway's migration from `iptables` to `nftables` and update the filter program running in userspace to reject all attack attempts.

**NICE Work Roles**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0117](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify security implications and apply methodologies within centralized and decentralized environments across the enterprise's computer systems in software development.
- [T0118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify security issues around steady state operation and management of software and incorporate security measures that must be taken when a product reaches its end of life.
- [T0175](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform real-time cyber defense incident handling (e.g., forensic collections, intrusion correlation and tracking, threat analysis, and direct system remediation) tasks to support deployable Incident Response Teams (IRTs).


## Background

A vulnerable server is hidden behind a NAT+Firewall combo gateway: `nat-fw`. The gateway relays 32-character requests consisting of hex digits to the server and the server's 32-character hex-digit replies to the client.

The `nat-fw` gateway should queue all requests to userspace where a running daemon analyzes them and allows them to proceed or drops them if an "attack" request is attempted by a client.

You have access to the `kali` machine(s) in the following network:

```
          devops            competitor
[server] <------> [nat-fw] <----+-----> [http://challenge.us]
 ubuntu            ubuntu       |
                                v
                             [kali]
```

The "vulnerability" the server must be protected against is any 32-character request with sufficient hex digits to contain a case-insensitive anagram of `deadbeef`. The `nat-fw` gateway used to run `iptables` but is now partially reconfigured to use `nftables` instead. NAT is implemented, but userspace queueing is missing.

## Getting Started

You have access to the `kali` machines. From `kali`,  log into `nat-fw` using `ssh`.

On `nat-fw`, you will see the old, commented-out, iptables-based NAT and userspace queueing settings in `/etc/rc.local`. The current port to `nftables` is in `/etc/nftables.conf`. You can start `iptables`-based userspace queueing while experimenting, but in the end everything should be configured exclusively via `nftables`: userspace queueing of requests should work, and `iptables-save` must return only lines that read:

```
# Table `nat' is incompatible, use 'nft' tool.
# Table `filter' is incompatible, use 'nft' tool.
```

All NAT and userspace queueing should appear in the output of:

```
nft list ruleset
```

>You may have to restart the `nat-fw` gateway to clear lingering `iptables` configuration left from your experimentation.

`nat-fw` runs a `user_filter` service via systemd containing the daemon responsible for discarding "attack" requests. It only discards requests starting with `deadbeef` instead of all requests containing an anagram of `deadbeef`. The C source code for the daemon is available here: `https://challenge.us/files`.  You must update this service to filter out all requests containing case-insensitive anagrams of `deadbeef`.

Any time you wish to receive feedback or be graded when both userspace queueing and  filtering `deadbeef` anagrams are set up), proceed to `http://challenge.us` and click the `Grade Challenge` button.


## Challenge Questions

1. Enter token for queueing to userspace.
2. Enter token for filtering DEADBEEF anagrams.
