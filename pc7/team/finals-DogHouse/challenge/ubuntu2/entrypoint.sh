#!/bin/bash
echo -e "service telnet\n{\ndisable = no\nflags = REUSE\nsocket_type = stream\nwait = no\nuser = root\nserver = /usr/sbin/telnetd\nlog_on_failure += USERID\n}" > /etc/xinetd.d/telnet
chmod 644 /etc/xinetd.d/telnet
service xinetd restart

exec /usr/sbin/xinetd -dontfork -stayalive -f /etc/xinetd.conf