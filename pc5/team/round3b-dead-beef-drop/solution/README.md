# Dead Beef Drop

*Solution Guide*

## Overview

*Dead Beef Drop* requires competitors to complete porting a NAT + userspace queueing (for firewall filtering) setup from `iptables` to `nftables`. Competitors must also write a comprehensive userspace filter that prevents *all* "attack" traffic from reaching the server while allowing all "regular" requests to pass through.

For both tasks, competitors should log into the `nat-fw` machine from their `kali` workstation(s), then `sudo` into the `root` account.

```bash
$ ssh nat-fw
...
user@nat-fw:~$ sudo -s
```

## Question 1

*Enter token for queueing to userspace*

View the old, non-functional `iptables` configuration:

```bash
cat /etc/rc.local

	#!/bin/sh

	# NOTE: Migrated to nftables!
	exit 0

	# DNAT (forward 31337 to serv):
	iptables -t nat -A PREROUTING -p tcp -i ens32 --dport 31337 \
			-j DNAT --to-destination 192.168.5.254:31337

	# Enqueue traffic to srv for userspace filtering:
	# (NOTE: `--queue-bypass` implies `ACCEPT` in the absence of userspace filter)
	iptables -A FORWARD -p tcp --dport 31337 \
			-j NFQUEUE --queue-num 0 --queue-bypass
```

This shows two `iptables` commands: 

- the first is configuring NAT to forward all tcp-31337 requests to the server connected over a private network (192.168.4.0/24)
- the second is queueing all such traffic to userspace where a program can examine each request and return an ALLOW or DROP verdict.

Running the following command...

```bash
systemctl status user_filter
```

...shows that the program, `/usr/sbin/user_filter`, is running and ready to issue the  verdicts.

Next, run:

```bash
nft list ruleset

	table ip nat {
		chain PREROUTING {
			type nat hook prerouting priority dstnat; policy accept;
			iifname "ens32" tcp dport 31337 counter packets 0 bytes 0 dnat to 192.168.5.254:31337
		}
	}
```

This matches the contents of `/etc/nftables.conf` and indicates only the NAT portion of the above `iptables` setup was ported over to `nftables`. Therefore, userspace queueing is not set up, and the `user_filter` service doesn't get to issue filtering verdicts.

A valid userspace queueing configuration for `nftables` can be obtained by configuring the second `iptables` rule on `nat-fw` and listing the output of `nft list ruleset` again. 

Alternatively,you could read the **man page** of `iptables-restore-translate` for a list of steps on how to convert the output of `iptables-save` into a valid list of `nftables` rules.

The final contents of `/etc/nftables.conf` should read as:

```bash
#!/usr/sbin/nft -f

flush ruleset

table ip nat {
	chain PREROUTING {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "ens32" tcp dport 31337 counter packets 0 bytes 0 dnat to 192.168.5.254:31337
	}
}

table ip filter {
	chain FORWARD {
		type filter hook forward priority filter; policy accept;
		tcp dport 31337 counter packets 0 bytes 0 queue flags bypass to 0
	}
}
```

**Note:**
The `nat-fw` machine might need to be rebooted to come back with a clean `nftables` configuration and no lingering `iptables` configuration. The output of `iptables-save` should read like this:

```
# Table `nat' is incompatible, use 'nft' tool.
# Table `filter' is incompatible, use 'nft' tool.
```

## Question 2

*Enter token for filtering DEADBEEF anagrams*

The server expects requests formatted as 32-character hex digits (`0-9a-f`), e.g.:

```
e988da013daec121a683dfdf2be79609
```

If such a request contains enough characters to form `deadbeef` (at least one occurrence each of `a`, `b`, and `f`, two occurrences of `d`, and three occurrences of `e`), then it is an "attack" and must be filtered out.

Let's focus our attention on the `user_filter` systemd service running on `nat-fw` and on its source code available at: `https://challenge.us/files/user_filter.c`.

In its current implementation, the C program calls an external helper, `/usr/share/pc5_user_filter/verdict`,  for the actual decision.

On `nat_fw`, we check for the presence and contents of this helper:

```bash
cat /usr/share/pc5_user_filter/verdict

	#!/bin/bash

	[[ $1 =~ "deadbeef" ]] && exit 1

	exit 0
```

Assuming `iptables` or `nftables`-based queueing of requests to userspace for `user_filter` to analyze is correctly set up, it appears we only reject requests that start with the exact sequence `deadbeef` as the first eight characters of the request.

The quickest way to filter all "attacks" (again, `deadbeef` anagrams) is to rewrite
this script as:

```bash
#!/bin/bash

# count occurrences of $CHR within $STR (case-insensitive):
chr_cnt() {
	local STR="$1"
	local CHR="$2"
	awk -F"${CHR,*}" '{print NF-1}' <<< "${STR,,*}"
}

let ACT=$(chr_cnt "$1" "a")
let BCT=$(chr_cnt "$1" "b")
let DCT=$(chr_cnt "$1" "d")
let ECT=$(chr_cnt "$1" "e")
let FCT=$(chr_cnt "$1" "f")

# reject bad (enough characters to make "deadbeef" anagram):
((ACT>=1 && BCT>=1 && DCT>=2 && ECT>=3 && FCT>=1)) && exit 1

# accept good:
exit 0
```

Proceed to `http://challenge.us` and click the **Grade Challenge** button. At this stage, full points for having solved the challenge should be awarded!
