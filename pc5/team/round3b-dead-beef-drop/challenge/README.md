# Dead Beef Drop

- [server/server.c](./server/pc5c46.c): source code for the simple request/response "server"
- [server/server.service](./server/server.service): systemd unit file for the server
- [nat-fw/user_filter/user_filter.c](./nat-fw/user_filter/user_filter.c): source for the `user_filter` daemon
- [nat-fw/user_filter/user_filter.service](./nat-fw/user_filter/user_filter.service): systemd unit for `user_filter`
- [nat-fw/user_filter/verdict](./nat-fw/user_filter/verdict): helper program for `user_filter` daemon
- [nat-fw/etc/rc.local](./nat-fw/etc/rc.local): old/obsolete `iptables` NAT and userspace queueing
- [nat-fw/etc/nftables.conf](./nat-fw/etc/nftables.conf): new `nftables` NAT rules
- [grading/GradingScript.sh](./grading/GradingScript.sh): challenge grading script
